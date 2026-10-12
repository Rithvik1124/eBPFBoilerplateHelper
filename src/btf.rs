//! Minimal BTF parser: reads /sys/kernel/btf/vmlinux (or any raw BTF blob)
//! and can render struct definitions as C-style declarations.
//! Spec: https://docs.kernel.org/bpf/btf.html  (little-endian only here)

use std::collections::HashMap;
use std::fmt::Write as _;

const BTF_MAGIC: u16 = 0xEB9F;
const MAX_DEPTH: u32 = 32; // guard against pathological/cyclic type chains

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Int, Ptr, Array, Struct, Union, Enum, Fwd, Typedef, Volatile, Const,
    Restrict, Func, FuncProto, Var, Datasec, Float, DeclTag, TypeTag, Enum64,
}

pub struct Member {
    pub name: String,
    pub ty: u32,
    pub bit_off: u32,
    pub bitfield: u32, // 0 if not a bitfield
}

pub struct Param {
    pub name: String,
    pub ty: u32,
}

pub struct Type {
    pub name: String,
    pub kind: Kind,
    pub kflag: bool,
    /// size in bytes for Int/Struct/Union/Enum/Float/Datasec,
    /// referenced type id for Ptr/Typedef/Const/Volatile/Restrict/TypeTag/Array(elem)/FuncProto(ret)/Func(proto)
    pub size_or_type: u32,
    pub nelems: u32,
    pub members: Vec<Member>,
    pub params: Vec<Param>,
}

pub struct Btf {
    pub types: Vec<Type>, // index 0 is the implicit `void`
    by_name: HashMap<String, Vec<u32>>,
}

fn rd32(d: &[u8], off: usize) -> Result<u32, String> {
    d.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("truncated BTF at offset {off}"))
}

fn cstr(strs: &[u8], off: u32) -> String {
    let s = strs.get(off as usize..).unwrap_or(&[]);
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..end]).into_owned()
}

impl Btf {
    pub fn parse(data: &[u8]) -> Result<Btf, String> {
        if data.len() < 24 {
            return Err("file too small to be BTF".into());
        }
        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(format!("bad BTF magic 0x{magic:04x} (big-endian BTF unsupported)"));
        }
        let hdr_len = rd32(data, 4)? as usize;
        let type_off = rd32(data, 8)? as usize;
        let type_len = rd32(data, 12)? as usize;
        let str_off = rd32(data, 16)? as usize;
        let str_len = rd32(data, 20)? as usize;

        let t0 = hdr_len + type_off;
        let s0 = hdr_len + str_off;
        let tsec = data.get(t0..t0 + type_len).ok_or("type section out of range")?;
        let strs = data.get(s0..s0 + str_len).ok_or("string section out of range")?;

        let mut types = vec![Type {
            name: "void".into(), kind: Kind::Int, kflag: false,
            size_or_type: 0, nelems: 0, members: vec![], params: vec![],
        }];

        let mut pos = 0usize;
        while pos < tsec.len() {
            // struct btf_type { u32 name_off; u32 info; u32 size_or_type; }
            let name_off = rd32(tsec, pos)?;
            let info = rd32(tsec, pos + 4)?;
            let sz = rd32(tsec, pos + 8)?;
            pos += 12;
            let kind_id = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;
            let kflag = (info >> 31) == 1;

            let mut t = Type {
                name: cstr(strs, name_off), kind: Kind::Int, kflag,
                size_or_type: sz, nelems: 0, members: vec![], params: vec![],
            };

            // Each kind may be followed by kind-specific trailing data.
            match kind_id {
                1 => { t.kind = Kind::Int; pos += 4; }
                2 => t.kind = Kind::Ptr,
                3 => {
                    // struct btf_array { u32 type; u32 index_type; u32 nelems; }
                    t.kind = Kind::Array;
                    t.size_or_type = rd32(tsec, pos)?;
                    t.nelems = rd32(tsec, pos + 8)?;
                    pos += 12;
                }
                4 | 5 => {
                    t.kind = if kind_id == 4 { Kind::Struct } else { Kind::Union };
                    for i in 0..vlen {
                        // struct btf_member { u32 name_off; u32 type; u32 offset; }
                        let b = pos + i * 12;
                        let n = rd32(tsec, b)?;
                        let ty = rd32(tsec, b + 4)?;
                        let off = rd32(tsec, b + 8)?;
                        // With kflag set, top 8 bits = bitfield size, low 24 = bit offset.
                        let (bit_off, bitfield) = if kflag { (off & 0xff_ffff, off >> 24) } else { (off, 0) };
                        t.members.push(Member { name: cstr(strs, n), ty, bit_off, bitfield });
                    }
                    pos += vlen * 12;
                }
                6 => { t.kind = Kind::Enum; pos += vlen * 8; }
                7 => t.kind = Kind::Fwd,
                8 => t.kind = Kind::Typedef,
                9 => t.kind = Kind::Volatile,
                10 => t.kind = Kind::Const,
                11 => t.kind = Kind::Restrict,
                12 => t.kind = Kind::Func,
                13 => {
                    t.kind = Kind::FuncProto;
                    for i in 0..vlen {
                        let b = pos + i * 8;
                        t.params.push(Param { name: cstr(strs, rd32(tsec, b)?), ty: rd32(tsec, b + 4)? });
                    }
                    pos += vlen * 8;
                }
                14 => { t.kind = Kind::Var; pos += 4; }
                15 => { t.kind = Kind::Datasec; pos += vlen * 12; }
                16 => t.kind = Kind::Float,
                17 => { t.kind = Kind::DeclTag; pos += 4; }
                18 => t.kind = Kind::TypeTag,
                19 => { t.kind = Kind::Enum64; pos += vlen * 12; }
                k => return Err(format!("unknown BTF kind {k}")),
            }
            types.push(t);
        }

        let mut by_name: HashMap<String, Vec<u32>> = HashMap::new();
        for (i, t) in types.iter().enumerate() {
            if !t.name.is_empty() {
                by_name.entry(t.name.clone()).or_default().push(i as u32);
            }
        }
        Ok(Btf { types, by_name })
    }

    fn ty(&self, id: u32) -> &Type {
        self.types.get(id as usize).unwrap_or(&self.types[0])
    }

    /// Peel typedefs / const / volatile / restrict / type tags.
    pub fn strip(&self, mut id: u32) -> u32 {
        for _ in 0..MAX_DEPTH {
            let t = self.ty(id);
            match t.kind {
                Kind::Typedef | Kind::Const | Kind::Volatile | Kind::Restrict | Kind::TypeTag => id = t.size_or_type,
                _ => break,
            }
        }
        id
    }

    pub fn size_of(&self, id: u32) -> u32 {
        let id = self.strip(id);
        let t = self.ty(id);
        match t.kind {
            Kind::Ptr => 8, // assumes a 64-bit target
            Kind::Array => t.nelems.saturating_mul(self.size_of(t.size_or_type)),
            Kind::Int | Kind::Struct | Kind::Union | Kind::Enum | Kind::Enum64 | Kind::Float | Kind::Datasec => t.size_or_type,
            _ => 0,
        }
    }

    /// Look up a struct/union by name. Accepts "task_struct" or "struct task_struct".
    pub fn find_struct(&self, name: &str) -> Option<u32> {
        let name = name.trim()
            .trim_start_matches("struct ")
            .trim_start_matches("union ")
            .trim();
        let ids = self.by_name.get(name)?;
        // Prefer a complete struct/union over a forward declaration.
        for &id in ids {
            let t = self.ty(id);
            if matches!(t.kind, Kind::Struct | Kind::Union) && t.size_or_type > 0 {
                return Some(id);
            }
        }
        // Fall back to a typedef that resolves to one.
        for &id in ids {
            if self.ty(id).kind == Kind::Typedef {
                let s = self.strip(id);
                if matches!(self.ty(s).kind, Kind::Struct | Kind::Union) {
                    return Some(s);
                }
            }
        }
        None
    }

    /// Names of structs containing `needle` (for discovering tracepoint ctx structs etc).
    pub fn search_structs(&self, needle: &str, limit: usize) -> Vec<String> {
        let mut v: Vec<String> = self.types.iter()
            .filter(|t| t.kind == Kind::Struct && t.size_or_type > 0 && t.name.contains(needle))
            .map(|t| t.name.clone())
            .collect();
        v.sort();
        v.dedup();
        v.truncate(limit);
        v
    }

    // ---------- C declaration rendering ----------

    /// Render `type declarator` the way C would, e.g. decl(ptr->int, "x") == "int *x".
    pub fn decl(&self, id: u32, declarator: &str) -> String {
        self.decl_inner(id, declarator.to_string(), 0)
    }

    fn join(base: &str, d: &str) -> String {
        if d.is_empty() { base.to_string() } else { format!("{base} {d}") }
    }

    fn decl_inner(&self, id: u32, d: String, depth: u32) -> String {
        if id == 0 {
            return Self::join("void", &d);
        }
        if depth > MAX_DEPTH {
            return Self::join("/*too deep*/", &d);
        }
        let t = self.ty(id);
        match t.kind {
            Kind::Ptr => {
                // Pointer to array / function needs parentheses: int (*p)[4], int (*f)(int)
                let target = self.ty(self.strip(t.size_or_type));
                let d2 = if matches!(target.kind, Kind::Array | Kind::FuncProto) {
                    format!("(*{d})")
                } else {
                    format!("*{d}")
                };
                self.decl_inner(t.size_or_type, d2, depth + 1)
            }
            Kind::Array => self.decl_inner(t.size_or_type, format!("{d}[{}]", t.nelems), depth + 1),
            Kind::FuncProto => {
                let mut ps: Vec<String> = t.params.iter().map(|p| {
                    if p.ty == 0 && p.name.is_empty() { "...".to_string() } else { self.decl_inner(p.ty, String::new(), depth + 1) }
                }).collect();
                if ps.is_empty() { ps.push("void".into()); }
                self.decl_inner(t.size_or_type, format!("{d}({})", ps.join(", ")), depth + 1)
            }
            Kind::Const => {
                // `int *const p` when applied to a pointer, `const int x` otherwise
                if self.ty(t.size_or_type).kind == Kind::Ptr {
                    self.decl_inner(t.size_or_type, format!("const {d}").trim_end().to_string(), depth + 1)
                } else {
                    format!("const {}", self.decl_inner(t.size_or_type, d, depth + 1))
                }
            }
            Kind::Volatile => format!("volatile {}", self.decl_inner(t.size_or_type, d, depth + 1)),
            Kind::Restrict => self.decl_inner(t.size_or_type, d, depth + 1), // `restrict` is noise here
            Kind::TypeTag => self.decl_inner(t.size_or_type, d, depth + 1),
            Kind::Struct => Self::join(&Self::tagged("struct", &t.name), &d),
            Kind::Union => Self::join(&Self::tagged("union", &t.name), &d),
            Kind::Enum | Kind::Enum64 => Self::join(&Self::tagged("enum", &t.name), &d),
            Kind::Fwd => Self::join(&Self::tagged(if t.kflag { "union" } else { "struct" }, &t.name), &d),
            Kind::Typedef | Kind::Int | Kind::Float => Self::join(&t.name, &d),
            _ => Self::join("/*?*/", &d),
        }
    }

    fn tagged(kw: &str, name: &str) -> String {
        if name.is_empty() { format!("{kw} {{...}}") } else { format!("{kw} {name}") }
    }

    // ---------- struct dump ----------

    /// Append a comment-table of a struct's fields. `depth` = how many levels of
    /// by-value nested structs to expand. Anonymous structs/unions are always flattened.
    pub fn dump_members(&self, out: &mut String, id: u32, base_bits: u32, level: usize, depth: u32) {
        let sid = self.strip(id);
        let t = self.ty(sid);
        if !matches!(t.kind, Kind::Struct | Kind::Union) {
            return;
        }
        for m in &t.members {
            let bits = base_bits + m.bit_off;
            let inner = self.ty(self.strip(m.ty));
            let is_agg = matches!(inner.kind, Kind::Struct | Kind::Union);

            if m.name.is_empty() && is_agg {
                self.dump_members(out, m.ty, bits, level, depth);
                continue;
            }
            let mut d = self.decl(m.ty, &m.name);
            let (off, size) = if m.bitfield > 0 {
                d.push_str(&format!(" : {}", m.bitfield));
                (format!("{}.{}", bits / 8, bits % 8), "-".to_string())
            } else {
                ((bits / 8).to_string(), self.size_of(m.ty).to_string())
            };
            let _ = writeln!(out, " *   {off:>7} {size:>6}  {}{d};", "    ".repeat(level));

            if is_agg && depth > 0 {
                self.dump_members(out, m.ty, bits, level + 1, depth - 1);
            }
        }
    }
}
