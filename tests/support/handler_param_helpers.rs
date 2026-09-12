// Copyright 2026 AlphaOne LLC
// SPDX-License-Identifier: Apache-2.0

//! #3632: source-level const resolution and raw-parameter helper call traversal.
//! Free-function calls passing `params` or `arguments` are followed transitively.
//! This is not type inference: method dispatch, macro expansion and renamed bags
//! remain outside this audit. Paths, imports and const aliases are resolved in
//! their lexical module, never by globally matching an identifier's final word.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use syn::visit::{self, Visit};

#[derive(Default)]
pub struct Index {
    constants: BTreeMap<String, (String, syn::Expr)>,
    imports: BTreeMap<String, (String, String)>,
    functions: Vec<Function>,
}

struct Function {
    name: String,
    scope: String,
    unit: Option<String>,
    reads: Vec<syn::Path>,
    calls: Vec<syn::Path>,
}

fn path_name(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|s| s.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn bag(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Path(p) => p.path.is_ident("params") || p.path.is_ident("arguments"),
        syn::Expr::Reference(r) => bag(&r.expr),
        syn::Expr::Paren(p) => bag(&p.expr),
        _ => false,
    }
}

#[derive(Default)]
struct Reads {
    keys: Vec<syn::Path>,
    calls: Vec<syn::Path>,
}

impl<'ast> Visit<'ast> for Reads {
    fn visit_expr_index(&mut self, expr: &'ast syn::ExprIndex) {
        if bag(&expr.expr)
            && let syn::Expr::Path(key) = &*expr.index
        {
            self.keys.push(key.path.clone());
        }
        visit::visit_expr_index(self, expr);
    }

    fn visit_expr_method_call(&mut self, expr: &'ast syn::ExprMethodCall) {
        if bag(&expr.receiver)
            && expr.method == "get"
            && let Some(syn::Expr::Path(key)) = expr.args.first()
        {
            self.keys.push(key.path.clone());
        }
        visit::visit_expr_method_call(self, expr);
    }

    fn visit_expr_call(&mut self, expr: &'ast syn::ExprCall) {
        if expr.args.iter().any(bag)
            && let syn::Expr::Path(callee) = &*expr.func
        {
            self.calls.push(callee.path.clone());
        }
        visit::visit_expr_call(self, expr);
    }

    // Nested items are separately indexed and are not executed by their parent.
    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<syn::Path>()
                .is_ok_and(|p| p.is_ident("test"))
    })
}

impl Index {
    pub fn add_file(&mut self, path: &Path, src: &str) -> syn::Result<()> {
        let mut parts: Vec<_> = path
            .with_extension("")
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        if parts
            .last()
            .is_some_and(|p| matches!(p.as_str(), "mod" | "lib"))
        {
            parts.pop();
        }
        // MCP declares #[path = "tools/..."] modules directly under mcp.
        if parts.starts_with(&["mcp".to_string(), "tools".to_string()]) {
            parts.remove(1);
        }
        let scope = if parts.is_empty() {
            "crate".to_string()
        } else {
            format!("crate::{}", parts.join("::"))
        };
        let unit = path
            .strip_prefix("mcp/tools")
            .ok()
            .map(|rel| super::module_unit(Path::new(""), rel));
        let parsed = syn::parse_file(src)?;
        self.items(&scope, unit.as_deref(), &parsed.items);
        Ok(())
    }

    fn items(&mut self, scope: &str, unit: Option<&str>, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Const(c) => {
                    if let syn::Type::Reference(r) = &*c.ty
                        && let syn::Type::Path(p) = &*r.elem
                        && p.path.is_ident("str")
                    {
                        self.constants.insert(
                            format!("{scope}::{}", c.ident),
                            (scope.to_string(), (*c.expr).clone()),
                        );
                    }
                }
                syn::Item::Use(u) => self.import(scope, "", &u.tree),
                syn::Item::Mod(m) if !test_only(&m.attrs) => {
                    if let Some((_, items)) = &m.content {
                        self.items(&format!("{scope}::{}", m.ident), unit, items);
                    }
                }
                syn::Item::Fn(f) if !test_only(&f.attrs) => {
                    self.function(scope, unit, &f.sig, &f.block);
                }
                syn::Item::Impl(i) if !test_only(&i.attrs) => {
                    for item in &i.items {
                        if let syn::ImplItem::Fn(f) = item
                            && !test_only(&f.attrs)
                        {
                            self.function(scope, unit, &f.sig, &f.block);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn import(&mut self, scope: &str, prefix: &str, tree: &syn::UseTree) {
        match tree {
            syn::UseTree::Path(p) => self.import(scope, &format!("{prefix}{}::", p.ident), &p.tree),
            syn::UseTree::Name(n) => {
                self.imports.insert(
                    format!("{scope}::{}", n.ident),
                    (scope.to_string(), format!("{prefix}{}", n.ident)),
                );
            }
            syn::UseTree::Rename(r) => {
                self.imports.insert(
                    format!("{scope}::{}", r.rename),
                    (scope.to_string(), format!("{prefix}{}", r.ident)),
                );
            }
            syn::UseTree::Group(g) => {
                for tree in &g.items {
                    self.import(scope, prefix, tree);
                }
            }
            syn::UseTree::Glob(_) => {}
        }
    }

    fn function(
        &mut self,
        scope: &str,
        unit: Option<&str>,
        sig: &syn::Signature,
        block: &syn::Block,
    ) {
        let name = format!("{scope}::{}", sig.ident);
        let mut reads = Reads::default();
        reads.visit_block(block);
        let locals: Vec<_> = block
            .stmts
            .iter()
            .filter_map(|stmt| {
                if let syn::Stmt::Item(item) = stmt {
                    Some(item.clone())
                } else {
                    None
                }
            })
            .collect();
        self.items(&name, unit, &locals);
        self.functions.push(Function {
            scope: name.clone(),
            name,
            unit: unit.map(str::to_string),
            reads: reads.keys,
            calls: reads.calls,
        });
    }

    fn resolve(&self, scope: &str, path: &str, seen: &mut BTreeSet<String>) -> String {
        if path.starts_with("crate::") {
            return self.expand(path, seen);
        }
        if let Some(tail) = path.strip_prefix("self::") {
            return self.expand(&format!("{scope}::{tail}"), seen);
        }
        if let Some(tail) = path.strip_prefix("super::") {
            let parent = scope.rsplit_once("::").map_or("crate", |(p, _)| p);
            return self.resolve(parent, tail, seen);
        }
        let mut current = scope;
        loop {
            let candidate = format!("{current}::{path}");
            let expanded = self.expand(&candidate, seen);
            if expanded != candidate
                || self.constants.contains_key(&candidate)
                || self.functions.iter().any(|f| f.name == candidate)
            {
                return expanded;
            }
            let Some((parent, _)) = current.rsplit_once("::") else {
                return candidate;
            };
            current = parent;
        }
    }

    fn expand(&self, path: &str, seen: &mut BTreeSet<String>) -> String {
        if !seen.insert(path.to_string()) {
            return path.to_string();
        }
        let mut prefix = path;
        loop {
            if let Some((scope, target)) = self.imports.get(prefix) {
                let resolved = self.resolve(scope, target, seen);
                return format!("{resolved}{}", &path[prefix.len()..]);
            }
            let Some((parent, _)) = prefix.rsplit_once("::") else {
                return path.to_string();
            };
            prefix = parent;
        }
    }

    fn const_value(
        &self,
        scope: &str,
        path: &syn::Path,
        seen: &mut BTreeSet<String>,
    ) -> Option<String> {
        let name = path_name(path);
        let scope = if (name.starts_with("self::") || name.starts_with("super::"))
            && self.functions.iter().any(|f| f.name == scope)
        {
            scope.rsplit_once("::").map_or("crate", |(p, _)| p)
        } else {
            scope
        };
        let resolved = self.resolve(scope, &name, &mut BTreeSet::new());
        if !seen.insert(resolved.clone()) {
            return None;
        }
        let (scope, expr) = self.constants.get(&resolved)?;
        match expr {
            syn::Expr::Lit(l) => {
                if let syn::Lit::Str(s) = &l.lit {
                    Some(s.value())
                } else {
                    None
                }
            }
            syn::Expr::Path(p) => self.const_value(scope, &p.path, seen),
            _ => None,
        }
    }

    pub fn unit_reads(&self) -> BTreeMap<String, BTreeSet<String>> {
        let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for root in &self.functions {
            let Some(unit) = &root.unit else {
                continue;
            };
            let mut pending = vec![root];
            let mut visited = BTreeSet::new();
            while let Some(function) = pending.pop() {
                if !visited.insert(&function.name) {
                    continue;
                }
                for key in &function.reads {
                    if let Some(value) =
                        self.const_value(&function.scope, key, &mut BTreeSet::new())
                    {
                        out.entry(unit.clone()).or_default().insert(value);
                    } else if key.segments.last().is_some_and(|s| {
                        let name = s.ident.to_string();
                        name.chars().any(char::is_uppercase)
                            && name
                                .chars()
                                .all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_')
                    }) {
                        panic!(
                            "#3632: unresolved const {} in {}; extend the resolver instead of skipping this read",
                            path_name(key),
                            function.name
                        );
                    }
                }
                for call in &function.calls {
                    // Function bodies have a lexical item scope for local consts/imports;
                    // `self`/`super` paths are relative to the containing module.
                    let module = function.name.rsplit_once("::").map_or("crate", |(p, _)| p);
                    let call_name = path_name(call);
                    let scope =
                        if call_name.starts_with("self::") || call_name.starts_with("super::") {
                            module
                        } else {
                            &function.scope
                        };
                    let target = self.resolve(scope, &call_name, &mut BTreeSet::new());
                    pending.extend(self.functions.iter().filter(|f| f.name == target));
                }
            }
        }
        out
    }
}
