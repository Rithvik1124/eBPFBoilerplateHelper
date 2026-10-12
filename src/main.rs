mod btf;

use btf::Btf;
use std::fmt::Write as _;
use std::{env, fs, process};

const USAGE: &str = "\
btfgen - generate eBPF boilerplate with struct fields (from live kernel BTF) as comments

USAGE:
  btfgen --fn NAME:RET:SECTION[:STRUCT,STRUCT,...] [--fn ...] [options]
  btfgen --find SUBSTRING

OPTIONS:
  --fn SPEC      function to generate; repeatable
  --depth N      expand N levels of by-value nested structs (default 0)
  --btf PATH     BTF file (default /sys/kernel/btf/vmlinux)
  --find STR     list struct names containing STR (e.g. trace_event_raw_sched)
  -o FILE        write output to FILE instead of stdout

EXAMPLE:
  btfgen --fn trace_exec:int:tp/syscalls/sys_enter_execve:task_struct --depth 1
  btfgen --fn on_fork:int:tp/sched/sched_process_fork -o probe.bpf.c

SECTIONS: tp/<cat>/<name> | tracepoint/<cat>/<name> | raw_tp/<name> | kprobe/<fn> | kretprobe/<fn>
";

struct FnSpec {
    name: String,
    ret: String,
    section: String,
    structs: Vec<String>,
}

fn parse_spec(s: &str) -> Result<FnSpec, String> {
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    if parts.len() < 3 || parts.iter().take(3).any(|p| p.trim().is_empty()) {
        return Err(format!("bad --fn '{s}': expected NAME:RET:SECTION[:STRUCTS]"));
    }
    let structs = parts.get(3)
        .map(|x| x.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    Ok(FnSpec {
        name: parts[0].trim().to_string(),
        ret: parts[1].trim().to_string(),
        section: parts[2].trim().to_string(),
        structs,
    })
}

/// Work out the ctx parameter for a section, and the BTF struct describing it (if any).
fn ctx_for(btf: &Btf, section: &str) -> Result<(String, Option<String>), String> {
    let (prefix, rest) = section.split_once('/').unwrap_or((section, ""));
    match prefix {
        "tp" | "tracepoint" => {
            let ev = rest.rsplit('/').next().unwrap_or("");
            let mut candidates = vec![format!("trace_event_raw_{ev}")];
            // All syscall enter/exit tracepoints share these generic ctx structs.
            if ev.starts_with("sys_enter") { candidates.push("trace_event_raw_sys_enter".into()); }
            if ev.starts_with("sys_exit") { candidates.push("trace_event_raw_sys_exit".into()); }
            for c in candidates {
                if btf.find_struct(&c).is_some() {
                    return Ok((format!("struct {c} *ctx"), Some(c)));
                }
            }
            Ok(("void *ctx /* TODO: ctx struct not in BTF, see /sys/kernel/tracing/events/<cat>/<name>/format */".into(), None))
        }
        "raw_tp" | "raw_tracepoint" => Ok(("struct bpf_raw_tracepoint_args *ctx".into(), Some("bpf_raw_tracepoint_args".into()))),
        "kprobe" | "kretprobe" => Ok(("struct pt_regs *ctx".into(), Some("pt_regs".into()))),
        other => Err(format!("unsupported section prefix '{other}' (try tp/, raw_tp/, kprobe/, kretprobe/)")),
    }
}

fn describe_struct(btf: &Btf, name: &str, depth: u32, out: &mut String) {
    match btf.find_struct(name) {
        Some(id) => {
            let t = &btf.types[btf.strip(id) as usize];
            let _ = writeln!(out, " * struct {} (size {} bytes)", t.name, t.size_or_type);
            let _ = writeln!(out, " *   {:>7} {:>6}  {}", "offset", "size", "field");
            btf.dump_members(out, id, 0, 0, depth);
        }
        None => {
            let _ = writeln!(out, " * struct {name}: NOT FOUND in BTF (typo, or not built into this kernel)");
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let mut specs = Vec::new();
    let mut depth = 0u32;
    let mut btf_path = "/sys/kernel/btf/vmlinux".to_string();
    let mut find: Option<String> = None;
    let mut outfile: Option<String> = None;

    while let Some(a) = args.next() {
        let mut val = |flag: &str| args.next().ok_or_else(|| format!("{flag} needs a value"));
        match a.as_str() {
            "--fn" => specs.push(parse_spec(&val("--fn")?)?),
            "--depth" => depth = val("--depth")?.parse().map_err(|_| "--depth must be a number")?,
            "--btf" => btf_path = val("--btf")?,
            "--find" => find = Some(val("--find")?),
            "-o" => outfile = Some(val("-o")?),
            "-h" | "--help" => { print!("{USAGE}"); return Ok(()); }
            other => return Err(format!("unknown argument '{other}'\n\n{USAGE}")),
        }
    }

    let data = fs::read(&btf_path).map_err(|e| format!("cannot read {btf_path}: {e}"))?;
    let btf = Btf::parse(&data)?;

    if let Some(needle) = find {
        for n in btf.search_structs(&needle, 200) { println!("{n}"); }
        return Ok(());
    }
    if specs.is_empty() {
        print!("{USAGE}");
        return Ok(());
    }

    let mut out = String::new();
    out.push_str("#include \"vmlinux.h\"\n#include <bpf/bpf_helpers.h>\n#include <bpf/bpf_tracing.h>\n#include <bpf/bpf_core_read.h>\n\n");
    out.push_str("char LICENSE[] SEC(\"license\") = \"GPL\";\n\n");

    for s in &specs {
        let (ctx_decl, ctx_struct) = ctx_for(&btf, &s.section)?;

        let mut to_describe: Vec<String> = ctx_struct.into_iter().collect();
        to_describe.extend(s.structs.iter().cloned());

        out.push_str("/*\n");
        for (i, name) in to_describe.iter().enumerate() {
            if i > 0 { out.push_str(" *\n"); }
            describe_struct(&btf, name, depth, &mut out);
        }
        out.push_str(" */\n");
        let _ = writeln!(out, "SEC(\"{}\")", s.section);
        let _ = writeln!(out, "{} {}({})\n{{", s.ret, s.name, ctx_decl);
        out.push_str("\t/* TODO */\n");
        if s.ret != "void" { out.push_str("\treturn 0;\n"); }
        out.push_str("}\n\n");
    }

    match outfile {
        Some(p) => fs::write(&p, out).map_err(|e| format!("cannot write {p}: {e}"))?,
        None => print!("{out}"),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        process::exit(1);
    }
}
