//! #3707 — no HTTP handler renders a store/driver error's `Display` into a
//! caller-facing JSON error body. A safe typed funnel already exists
//! (`postgres_gate::store_err_to_response`, `errors::handler_error_500`); the
//! sites this pin guards were hand-rolled bypasses around it.
//!
//! This DERIVES its site list by scanning the handler sources for the leak
//! SHAPE, rather than naming the eight sites the issue happened to find. A pin
//! that asserts N named sites are clean cannot see site N+1 and passes
//! precisely because someone forgot one.

use std::path::Path;

/// Sites whose error is OUR OWN closed vocabulary, not foreign text.
///
/// Bound to the EXACT line, not a `file:line` pair: a line number rots on the
/// next edit above it, and a whole-file exemption would hide a real leak added
/// later in the same file. If the text changes at all the pin re-fires and the
/// reason has to be re-argued — which is the point.
///
/// `validate_source_uri` is our own validator rejecting the CALLER'S OWN input
/// and returning our own message about it. Nothing foreign reaches the body,
/// and flattening it to "invalid request" would trade a leak we do not have for
/// a support ticket we would.
const ALLOWED: &[&str] = &[r#"Json(json!({"error": format!("invalid source_uri filter: {e}")})),"#];

/// `format!("… {e}")` / `e.to_string()` flowing into a JSON `"error"` body.
fn leak_sites(src: &str) -> Vec<(usize, String)> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line.starts_with("//") || line.starts_with("///") {
            continue;
        }
        let json_error_body = line.contains(r#""error""#)
            && (line.contains("format!(") || line.contains("e.to_string()"));
        let interpolates_err =
            line.contains("{e}") || line.contains("{detail}") || line.contains("e.to_string()");
        if !(json_error_body && interpolates_err) || ALLOWED.contains(&line) {
            continue;
        }
        // NARROWED to the actual defect class. #3707 is about a STORE / DRIVER
        // error's `Display` crossing to a caller. Our own validators returning
        // our own message about the CALLER'S OWN input are a closed vocabulary
        // and are explicitly NOT this defect -- flattening them would trade a
        // leak we do not have for a support ticket we would.
        //
        // So the binding must originate in a store/db call. Look back over the
        // enclosing statement for one. A pin that fires on every `{e}` trains
        // people to ignore it, and an instrument nobody reads is worse than a
        // missing one.
        let lo = i.saturating_sub(12);
        let ctx = lines[lo..=i].join("\n");
        let store_origin = ctx.contains("app.store.")
            || ctx.contains("db::")
            || ctx.contains(".store\n")
            || ctx.contains("self.store");
        // A DOWNCAST to one of OUR OWN error types means the site is rendering
        // a TYPED VARIANT we authored, not a driver's `Display`. `links.rs`
        // states that contract outright -- its body shape is byte-identical to
        // v0.7.0 GA on purpose. That is the opposite of this defect, and
        // flattening it would break a published response shape.
        let renders_our_typed_variant = ctx.contains("downcast_ref::<")
            && (ctx.contains("StorageError") || ctx.contains("StoreError"));
        if store_origin && !renders_our_typed_variant {
            out.push((i + 1, line.to_string()));
        }
    }
    out
}

#[test]
fn no_handler_renders_a_driver_error_into_a_caller_body_3707() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/handlers");
    let mut offenders: Vec<String> = Vec::new();
    let mut scanned = 0usize;

    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("read_dir src/handlers") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let src = std::fs::read_to_string(&path).expect("read handler source");
            scanned += 1;
            for (line, text) in leak_sites(&src) {
                let rel = path
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(&path);
                offenders.push(format!("{}:{line}: {text}", rel.display()));
            }
        }
    }

    // PRESENCE — pairs the absence assertion below on the same sink. Without
    // this the test would pass just as happily if the scan silently walked zero
    // files (a moved directory, a changed extension), which is the shape that
    // turns a structural gate into decoration.
    assert!(
        scanned >= 10,
        "#3707: the scan must actually read the handler sources; only {scanned} file(s) seen"
    );

    assert!(
        offenders.is_empty(),
        "#3707: {} handler site(s) render a driver/store error into a caller-facing \
         JSON body. Route them through `store_err_to_response` (pg) or \
         `handler_error_500` (sqlite) and put the detail on a `tracing` line:\n  {}",
        offenders.len(),
        offenders.join("\n  ")
    );
}
