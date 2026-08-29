// SPDX-License-Identifier: MIT OR Apache-2.0
// This file is part of Nitr.
// See https://nitrweb.com/ for more information
// Copyright (C) 2024-present Jose Quintana <joseluisq.net>

//! The machine-readable `nitr.*` API description and its generators.
//!
//! One source of truth (`nitr-api.toml`) produces the LuaCATS type
//! definitions (editor completion via the Lua Language Server) and the
//! reference page. Tests assert that every registered `nitr.*` entry
//! appears in the description and that the generated files are current —
//! hand-written stubs drift within one release, and stale autocomplete is
//! worse than none.

use serde::Deserialize;

/// The description source, compiled into the binary.
pub const SOURCE: &str = include_str!("nitr-api.toml");

#[derive(Deserialize)]
pub struct Api {
    #[serde(default, rename = "class")]
    pub classes: Vec<Class>,
    #[serde(default, rename = "fn")]
    pub fns: Vec<FnEntry>,
    #[serde(default, rename = "table")]
    pub tables: Vec<TableEntry>,
}

#[derive(Deserialize)]
pub struct Class {
    pub name: String,
    pub desc: String,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Deserialize)]
pub struct Field {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub desc: String,
}

#[derive(Deserialize)]
pub struct FnEntry {
    pub name: String,
    #[serde(default)]
    pub feature: String,
    pub desc: String,
    #[serde(default)]
    pub params: Vec<Param>,
    #[serde(default)]
    pub returns: Vec<Ret>,
    /// Present when the function is also a namespace (`nitr.json`,
    /// `nitr.csrf`): a callable table with these members.
    #[serde(default)]
    pub methods: Vec<Member>,
}

#[derive(Deserialize)]
pub struct TableEntry {
    pub name: String,
    #[serde(default)]
    pub feature: String,
    pub desc: String,
    /// Colon-style members (`nitr.db:query`).
    #[serde(default)]
    pub methods: Vec<Member>,
    /// Dot-style members (`nitr.time.now`).
    #[serde(default)]
    pub functions: Vec<Member>,
    /// Plain data members (`nitr.crypto.max_password_bytes`): constants a
    /// script reads rather than calls.
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Deserialize)]
pub struct Member {
    pub name: String,
    /// A dot-style member on an otherwise callable entry.
    #[serde(default)]
    pub dot: bool,
    #[serde(default)]
    pub params: Vec<Param>,
    #[serde(default)]
    pub returns: Vec<Ret>,
    pub desc: String,
}

#[derive(Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub desc: String,
}

#[derive(Deserialize)]
pub struct Ret {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub desc: String,
}

pub fn parse() -> anyhow::Result<Api> {
    toml::from_str(SOURCE).map_err(|err| anyhow::anyhow!("invalid nitr-api.toml: {err}"))
}

impl Api {
    /// Every dotted path the description covers, for the completeness test.
    pub fn known_paths(&self) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        for f in &self.fns {
            out.insert(f.name.clone());
            for m in &f.methods {
                out.insert(format!("{}.{}", f.name, m.name));
            }
        }
        for t in &self.tables {
            out.insert(t.name.clone());
            for m in t.methods.iter().chain(&t.functions) {
                out.insert(format!("{}.{}", t.name, m.name));
            }
            for field in &t.fields {
                out.insert(format!("{}.{}", t.name, field.name));
            }
        }
        out
    }
}

/// A `---@param` line: a trailing `?` on the type marks it optional.
fn param_line(p: &Param) -> String {
    let (name, ty) = match p.ty.strip_suffix('?') {
        Some(ty) if p.name != "..." => (format!("{}?", p.name), ty),
        Some(ty) => (p.name.clone(), ty),
        None => (p.name.clone(), p.ty.as_str()),
    };
    match p.desc.is_empty() {
        true => format!("---@param {name} {ty}"),
        false => format!("---@param {name} {ty} {}", p.desc),
    }
}

fn arg_list(params: &[Param]) -> String {
    params
        .iter()
        .map(|p| p.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Emits one annotated `function ... end` stub.
fn emit_fn(out: &mut String, target: &str, member: &Member, sep: char) {
    out.push_str(&format!("---{}\n", member.desc));
    for p in &member.params {
        out.push_str(&param_line(p));
        out.push('\n');
    }
    for r in &member.returns {
        match r.desc.is_empty() {
            true => out.push_str(&format!("---@return {}\n", r.ty)),
            false => out.push_str(&format!("---@return {} _ {}\n", r.ty, r.desc)),
        }
    }
    out.push_str(&format!(
        "function {target}{sep}{}({}) end\n\n",
        member.name,
        arg_list(&member.params)
    ));
}

/// A `fun(...)` type for `---@overload`.
fn fun_type(params: &[Param], returns: &[Ret]) -> String {
    let params = params
        .iter()
        .map(|p| format!("{}: {}", p.name, p.ty))
        .collect::<Vec<_>>()
        .join(", ");
    let rets = returns
        .iter()
        .map(|r| r.ty.clone())
        .collect::<Vec<_>>()
        .join(", ");
    match rets.is_empty() {
        true => format!("fun({params})"),
        false => format!("fun({params}): {rets}"),
    }
}

fn feature_note(feature: &str) -> String {
    match feature {
        "" => String::new(),
        "test" => " (available in `nitr test` files)".into(),
        "cfg" => " (set when a `config_script` is configured)".into(),
        f => format!(" (std feature: `{f}`)"),
    }
}

/// Generates the LuaCATS definitions file (`resources/nitr-types.lua`).
pub fn emit_types(api: &Api) -> String {
    let mut out = String::from(
        "---@meta nitr\n\
         -- GENERATED by `nitr` from nitr-api.toml — do not edit by hand.\n\
         -- Editor completion for the whole `nitr.*` surface: keep this file\n\
         -- next to your scripts (the Lua Language Server picks it up).\n\n\
         ---@class nitr\nnitr = {}\n\n",
    );

    for class in &api.classes {
        let local = class.name.rsplit('.').next().unwrap_or(&class.name);
        out.push_str(&format!("---{}\n---@class {}\n", class.desc, class.name));
        for field in &class.fields {
            out.push_str(&format!(
                "---@field {} {} {}\n",
                field.name, field.ty, field.desc
            ));
        }
        out.push_str(&format!("local {local} = {{}}\n\n"));
        for f in api.fns.iter().filter(|f| {
            f.name
                .strip_prefix(class.name.as_str())
                .is_some_and(|rest| rest.starts_with(':'))
        }) {
            let member = Member {
                name: f.name.split(':').next_back().unwrap_or_default().into(),
                dot: false,
                params: f.params.iter().map(clone_param).collect(),
                returns: f.returns.iter().map(clone_ret).collect(),
                desc: f.desc.clone(),
            };
            emit_fn(&mut out, local, &member, ':');
        }
    }

    for f in api.fns.iter().filter(|f| !f.name.contains(':')) {
        let desc = format!("{}{}", f.desc, feature_note(&f.feature));
        if f.methods.is_empty() {
            let member = Member {
                name: f.name.rsplit('.').next().unwrap_or(&f.name).into(),
                dot: false,
                params: f.params.iter().map(clone_param).collect(),
                returns: f.returns.iter().map(clone_ret).collect(),
                desc,
            };
            emit_fn(&mut out, "nitr", &member, '.');
        } else {
            // Callable namespace: a class carrying an `@overload` for the
            // call form, then its members.
            out.push_str(&format!(
                "---{desc}\n---@class {}\n---@overload {}\n{} = {{}}\n\n",
                f.name,
                fun_type(&f.params, &f.returns),
                f.name
            ));
            for m in &f.methods {
                emit_fn(&mut out, &f.name, m, if m.dot { '.' } else { ':' });
            }
        }
    }

    for t in &api.tables {
        out.push_str(&format!(
            "---{}{}\n{} = {{}}\n\n",
            t.desc,
            feature_note(&t.feature),
            t.name
        ));
        // Data members before the callables, the way a reader meets them.
        // The placeholder value is never the point — `---@type` is what
        // the language server reads; the real value lives server-side.
        for field in &t.fields {
            out.push_str(&format!(
                "---{}\n---@type {}\n{}.{} = nil\n\n",
                field.desc, field.ty, t.name, field.name
            ));
        }
        for m in &t.methods {
            emit_fn(&mut out, &t.name, m, ':');
        }
        for m in &t.functions {
            emit_fn(&mut out, &t.name, m, '.');
        }
    }

    out
}

fn clone_param(p: &Param) -> Param {
    Param {
        name: p.name.clone(),
        ty: p.ty.clone(),
        desc: p.desc.clone(),
    }
}

fn clone_ret(r: &Ret) -> Ret {
    Ret {
        ty: r.ty.clone(),
        desc: r.desc.clone(),
    }
}

/// One signature line for the reference page.
fn signature(name: &str, params: &[Param], returns: &[Ret]) -> String {
    let params = params
        .iter()
        .map(|p| p.name.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let rets = returns
        .iter()
        .map(|r| r.ty.clone())
        .collect::<Vec<_>>()
        .join(", ");
    match rets.is_empty() {
        true => format!("{name}({params})"),
        false => format!("{name}({params}) -> {rets}"),
    }
}

/// Generates the Markdown reference page (`resources/nitr-api.md`).
pub fn emit_docs(api: &Api) -> String {
    let mut out = String::from(
        "# The `nitr.*` API\n\n\
         <!-- GENERATED by `nitr` from nitr-api.toml — do not edit by hand. -->\n\n\
         The whole surface Nitr exposes to Lua, one namespace. Entries marked\n\
         with a *std feature* need that name in `[std] features`.\n\n",
    );

    out.push_str("## Functions and modules\n\n");
    for f in api.fns.iter().filter(|f| !f.name.contains(':')) {
        out.push_str(&format!(
            "### `{}`{}\n\n{}\n\n",
            signature(&f.name, &f.params, &f.returns),
            feature_note(&f.feature),
            f.desc
        ));
        for m in &f.methods {
            let sep = if m.dot { "." } else { ":" };
            out.push_str(&format!(
                "- `{}` — {}\n",
                signature(&format!("{}{sep}{}", f.name, m.name), &m.params, &m.returns),
                m.desc
            ));
        }
        if !f.methods.is_empty() {
            out.push('\n');
        }
    }
    for t in &api.tables {
        out.push_str(&format!(
            "### `{}`{}\n\n{}\n\n",
            t.name,
            feature_note(&t.feature),
            t.desc
        ));
        for m in &t.methods {
            out.push_str(&format!(
                "- `{}` — {}\n",
                signature(&format!("{}:{}", t.name, m.name), &m.params, &m.returns),
                m.desc
            ));
        }
        for m in &t.functions {
            out.push_str(&format!(
                "- `{}` — {}\n",
                signature(&format!("{}.{}", t.name, m.name), &m.params, &m.returns),
                m.desc
            ));
        }
        for field in &t.fields {
            out.push_str(&format!(
                "- `{}.{}: {}` — {}\n",
                t.name, field.name, field.ty, field.desc
            ));
        }
        if !t.methods.is_empty() || !t.functions.is_empty() || !t.fields.is_empty() {
            out.push('\n');
        }
    }

    out.push_str("## Types\n\n");
    for class in &api.classes {
        out.push_str(&format!("### `{}`\n\n{}\n\n", class.name, class.desc));
        for field in &class.fields {
            out.push_str(&format!(
                "- `{}: {}` — {}\n",
                field.name, field.ty, field.desc
            ));
        }
        let methods: Vec<&FnEntry> = api
            .fns
            .iter()
            .filter(|f| {
                f.name
                    .strip_prefix(class.name.as_str())
                    .is_some_and(|rest| rest.starts_with(':'))
            })
            .collect();
        for f in methods {
            let name = f.name.split(':').next_back().unwrap_or_default();
            out.push_str(&format!(
                "- `{}` — {}\n",
                signature(&format!(":{name}"), &f.params, &f.returns),
                f.desc
            ));
        }
        out.push('\n');
    }

    out
}
