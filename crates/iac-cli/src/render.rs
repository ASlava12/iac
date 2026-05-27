use iac_core::{
    diff::{Diff, DiffKind, FieldChange},
    executor::{ApplyItem, ApplyResult, ItemStatus, PlanItem, PlanResult},
};
use serde_yaml_ng::Value as YamlValue;
use std::io::Write;

pub fn plan_human<W: Write>(plan: &PlanResult, mut out: W) -> std::io::Result<()> {
    let changed: Vec<&PlanItem> = plan.items.iter().filter(|i| i.diff.is_change()).collect();
    let unchanged = plan.items.len() - changed.len();
    let total_steps: usize = changed.iter().map(|i| i.steps.len()).sum();

    writeln!(
        out,
        "Plan: {} change(s), {} unchanged. {} step(s).",
        changed.len(),
        unchanged,
        total_steps
    )?;
    writeln!(out, "Operation: {}", plan.operation.id)?;
    writeln!(out)?;

    if changed.is_empty() {
        writeln!(out, "  (no changes)")?;
        return Ok(());
    }

    for item in &changed {
        let marker = diff_marker(&item.diff);
        writeln!(out, "  [{marker}] {}", item.resource_id)?;
        for reason in &item.diff.reasons {
            writeln!(out, "        # {reason}")?;
        }
        for change in &item.diff.changes {
            writeln!(out, "        {}", format_change(change))?;
        }
        if !item.steps.is_empty() {
            writeln!(out, "        steps:")?;
            for s in &item.steps {
                writeln!(out, "          - {}: {}", s.action, s.description)?;
            }
        }
    }

    if unchanged > 0 {
        writeln!(out)?;
        writeln!(out, "  ({unchanged} unchanged)")?;
    }
    Ok(())
}

pub fn apply_human<W: Write>(result: &ApplyResult, mut out: W) -> std::io::Result<()> {
    writeln!(out, "Operation: {}", result.operation.id)?;
    writeln!(out, "Status: {:?}", result.operation.status)?;
    writeln!(out)?;

    let mut succeeded = 0;
    let mut failed = 0;
    let mut no_change = 0;

    for item in &result.items {
        match item.status {
            ItemStatus::NoChange => no_change += 1,
            ItemStatus::Succeeded => succeeded += 1,
            ItemStatus::Failed => failed += 1,
            ItemStatus::Skipped => {}
        }
        write_item(&mut out, item)?;
    }

    writeln!(out)?;
    writeln!(
        out,
        "Summary: {succeeded} ok, {failed} failed, {no_change} unchanged"
    )?;
    Ok(())
}

fn write_item<W: Write>(out: &mut W, item: &ApplyItem) -> std::io::Result<()> {
    let marker = match item.status {
        ItemStatus::NoChange => '=',
        ItemStatus::Succeeded => '+',
        ItemStatus::Failed => '!',
        ItemStatus::Skipped => '·',
    };
    writeln!(out, "  [{marker}] {}", item.resource_id)?;
    for s in &item.steps {
        let status = format!("{:?}", s.step.status).to_lowercase();
        writeln!(
            out,
            "        {}: {} -> {}",
            s.step.action, s.step.description, status
        )?;
        if let Some(err) = &s.result.error {
            writeln!(out, "          error: {err}")?;
        }
    }
    if let Some(v) = &item.verify
        && !v.matched
    {
        writeln!(out, "        verify: MISMATCH")?;
        if let Some(changes) = &v.mismatch {
            for c in changes {
                writeln!(out, "          {}", format_change(c))?;
            }
        }
    }
    if let Some(err) = &item.error {
        writeln!(out, "        error: {err}")?;
    }
    Ok(())
}

fn diff_marker(diff: &Diff) -> char {
    match diff.kind {
        DiffKind::Create => '+',
        DiffKind::Update => '~',
        DiffKind::Delete => '-',
        DiffKind::NoChange => '=',
    }
}

fn format_change(change: &FieldChange) -> String {
    if change.sensitive {
        return format!("{}: <sensitive> -> <sensitive>", change.field);
    }
    let from = change
        .from
        .as_ref()
        .map(yaml_inline)
        .unwrap_or_else(|| "<absent>".into());
    let to = change
        .to
        .as_ref()
        .map(yaml_inline)
        .unwrap_or_else(|| "<absent>".into());
    format!("{}: {} -> {}", change.field, from, to)
}

pub fn yaml_inline(value: &YamlValue) -> String {
    match value {
        YamlValue::Null => "null".into(),
        YamlValue::Bool(b) => b.to_string(),
        YamlValue::Number(n) => n.to_string(),
        YamlValue::String(s) => {
            if s.contains('\n') {
                format!("<{} bytes>", s.len())
            } else {
                format!("{s:?}")
            }
        }
        YamlValue::Sequence(_) | YamlValue::Mapping(_) | YamlValue::Tagged(_) => {
            serde_yaml_ng::to_string(value)
                .map(|s| s.trim().replace('\n', " "))
                .unwrap_or_else(|_| "<unprintable>".into())
        }
    }
}
