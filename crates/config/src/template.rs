use std::{collections::BTreeSet, str::FromStr};

use toml_edit::{DocumentMut, Item, Table};

use crate::RuntimeConfig;

pub const CONFIG_TEMPLATE: &str = include_str!("../../../res/config.default.toml");

pub(crate) const TEMPLATE_EXAMPLES: &[&str] = &[
    "runtime.patterns_url",
    "apps.shared.include",
    "apps.shared.exclude",
    "manifest.providers",
    "[debug]",
    "debug.control_api",
    "[[apps.inject]]",
    "apps.inject[].id",
    "apps.inject[].dlc",
    "apps.inject[].ticket",
    "apps.inject[].purchase_time",
    "[app_avatar]",
    "app_avatar.480",
    "app_avatar.0",
    "[[app_avatar.rules]]",
    "app_avatar.rules[].flag",
    "app_avatar.rules[].avatar",
    "app_avatar.rules[].apps",
    "app_avatar.rules[].exclude",
    "[[library_inject.libs]]",
    "library_inject.libs[].path",
    "library_inject.libs[].flag",
    "library_inject.libs[].apps",
    "library_inject.libs[].exclude",
];

#[derive(Debug, Clone)]
pub struct TemplateSyncDryRun {
    pub changed: bool,
    pub synced: String,
    pub added_fields: Vec<String>,
    pub kept_commented_examples: Vec<String>,
    pub pruned_commented_examples: Vec<String>,
}

impl RuntimeConfig {
    pub fn write_default_template(path: &std::path::Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        std::io::Write::write_all(&mut file, CONFIG_TEMPLATE.as_bytes())
    }

    pub fn sync_default_template(path: &std::path::Path) -> std::io::Result<bool> {
        let text = std::fs::read_to_string(path)?;
        let dry_run = Self::sync_default_template_dry_run(&text)?;
        if !dry_run.changed {
            return Ok(false);
        }
        std::fs::write(path, dry_run.synced)?;
        Ok(true)
    }

    pub fn sync_default_template_dry_run(text: &str) -> std::io::Result<TemplateSyncDryRun> {
        let document = parse_document(text)?;
        let template_examples = TEMPLATE_EXAMPLES
            .iter()
            .map(|example| (*example).to_owned())
            .collect::<Vec<_>>();
        let template_text = prune_commented_section_examples(CONFIG_TEMPLATE, document.as_table());
        let mut template = parse_document(&template_text)?;
        let added_fields = collect_added_template_fields(template.as_table(), document.as_table());

        merge_user_values_into_template(template.as_table_mut(), document.as_table());
        let mut position = 0;
        assign_table_positions(template.as_table_mut(), &mut position);

        let synced = template.to_string();
        let synced_examples: BTreeSet<_> =
            collect_commented_examples(&synced).into_iter().collect();
        let kept_commented_examples = template_examples
            .iter()
            .filter(|example| synced_examples.contains(*example))
            .cloned()
            .collect();
        let pruned_commented_examples = template_examples
            .into_iter()
            .filter(|example| !synced_examples.contains(example))
            .collect();
        Ok(TemplateSyncDryRun {
            changed: synced != text,
            synced,
            added_fields,
            kept_commented_examples,
            pruned_commented_examples,
        })
    }
}

fn parse_document(text: &str) -> std::io::Result<DocumentMut> {
    DocumentMut::from_str(text).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct CommentedSectionHeader {
    pub(crate) path: Vec<String>,
    pub(crate) array: bool,
}

fn prune_commented_section_examples(template: &str, user: &Table) -> String {
    let mut output = Vec::new();
    let mut lines = template.split_inclusive('\n').peekable();

    while let Some(line) = lines.next() {
        let header = parse_commented_section_header(line);
        let should_prune = header
            .as_ref()
            .is_some_and(|header| user_has_section(user, header));

        if should_prune {
            prune_preceding_comment_description(&mut output);
            while let Some(next) = lines.peek() {
                if next.trim().is_empty() || parse_commented_section_header(next).is_some() {
                    break;
                }
                if next.trim_start().starts_with('#') {
                    let _ = lines.next();
                    continue;
                }
                break;
            }
            continue;
        }

        output.push(line);
    }

    output.concat()
}

fn prune_preceding_comment_description(output: &mut Vec<&str>) {
    while output.last().is_some_and(|line| {
        line.trim_start().starts_with('#') && parse_commented_section_header(line).is_none()
    }) {
        let _ = output.pop();
    }
}

pub(crate) fn parse_commented_section_header(line: &str) -> Option<CommentedSectionHeader> {
    let commented = line.trim_start().strip_prefix('#')?.trim_start();

    if let Some(rest) = commented.strip_prefix("[[") {
        let end = rest.find("]]")?;
        return Some(CommentedSectionHeader {
            path: split_section_path(&rest[..end]),
            array: true,
        });
    }

    if let Some(rest) = commented.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(CommentedSectionHeader {
            path: split_section_path(&rest[..end]),
            array: false,
        });
    }

    None
}

fn split_section_path(path: &str) -> Vec<String> {
    path.split('.')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn format_commented_section_header(header: &CommentedSectionHeader) -> String {
    let path = header.path.join(".");
    if header.array {
        format!("[[{path}]]")
    } else {
        format!("[{path}]")
    }
}

fn collect_commented_examples(text: &str) -> Vec<String> {
    let mut examples = Vec::new();
    let mut current_section = Vec::<String>::new();
    let mut current_array = false;

    for line in text.lines() {
        if let Some(header) = parse_section_header(line) {
            current_section = header.path;
            current_array = header.array;
            continue;
        }

        if let Some(header) = parse_commented_section_header(line) {
            examples.push(format_commented_section_header(&header));
            current_section = header.path;
            current_array = header.array;
            continue;
        }

        let Some(commented) = line.trim_start().strip_prefix('#') else {
            continue;
        };
        let Some(key) = commented.split_once('=').map(|(key, _)| key.trim()) else {
            continue;
        };
        if key.is_empty() || key.starts_with('[') {
            continue;
        }
        examples.push(format_commented_field_example(
            &current_section,
            current_array,
            key,
        ));
    }

    examples
}

fn parse_section_header(line: &str) -> Option<CommentedSectionHeader> {
    let line = line.trim_start();

    if let Some(rest) = line.strip_prefix("[[") {
        let end = rest.find("]]")?;
        return Some(CommentedSectionHeader {
            path: split_section_path(&rest[..end]),
            array: true,
        });
    }

    if let Some(rest) = line.strip_prefix('[') {
        let end = rest.find(']')?;
        return Some(CommentedSectionHeader {
            path: split_section_path(&rest[..end]),
            array: false,
        });
    }

    None
}

fn format_commented_field_example(section: &[String], array: bool, key: &str) -> String {
    let key = key.trim_matches('"');
    if section.is_empty() {
        return key.to_owned();
    }

    let mut path = section.to_vec();
    if array {
        if let Some(last) = path.last_mut() {
            last.push_str("[]");
        }
    }
    path.push(key.to_owned());
    path.join(".")
}

fn user_has_section(table: &Table, header: &CommentedSectionHeader) -> bool {
    let Some((last, parents)) = header.path.split_last() else {
        return false;
    };

    let mut current = table;
    for part in parents {
        let Some(next) = current.get(part).and_then(|item| item.as_table()) else {
            return false;
        };
        current = next;
    }

    let Some(item) = current.get(last) else {
        return false;
    };

    if header.array {
        return item.as_array_of_tables().is_some();
    }

    item.as_inline_table().is_some()
        || item
            .as_table()
            .is_some_and(|table| !table.is_implicit() || !table.is_empty())
}

fn merge_user_values_into_template(template: &mut Table, user: &Table) {
    for (key, user_item) in user.iter() {
        match template.get_mut(key) {
            Some(template_item) => {
                if let (Some(template_table), Some(user_table)) =
                    (template_item.as_table_mut(), user_item.as_table())
                {
                    merge_user_values_into_template(template_table, user_table);
                } else {
                    *template_item = user_item.clone();
                }
            }
            None => {
                template.insert(key, user_item.clone());
            }
        }
    }
}

fn collect_added_template_fields(template: &Table, user: &Table) -> Vec<String> {
    let mut fields = Vec::new();
    collect_missing_fields(template, user, "", &mut fields);
    fields
}

fn collect_missing_fields(template: &Table, user: &Table, prefix: &str, fields: &mut Vec<String>) {
    for (key, template_item) in template.iter() {
        let path = join_path(prefix, key);
        match template_item {
            Item::Table(template_table) => {
                if let Some(user_table) = user.get(key).and_then(Item::as_table) {
                    collect_missing_fields(template_table, user_table, &path, fields);
                } else {
                    collect_value_paths(template_table, &path, fields);
                }
            }
            Item::ArrayOfTables(template_array) => {
                if user.get(key).and_then(Item::as_array_of_tables).is_none()
                    && !template_array.is_empty()
                {
                    fields.push(format!("{path}[]"));
                }
            }
            _ => {
                if user.get(key).is_none() {
                    fields.push(path);
                }
            }
        }
    }
}

fn collect_value_paths(table: &Table, prefix: &str, fields: &mut Vec<String>) {
    for (key, item) in table.iter() {
        let path = join_path(prefix, key);
        match item {
            Item::Table(child) => collect_value_paths(child, &path, fields),
            Item::ArrayOfTables(array) if !array.is_empty() => fields.push(format!("{path}[]")),
            Item::ArrayOfTables(_) => {}
            _ => fields.push(path),
        }
    }
}

fn join_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_owned()
    } else {
        format!("{prefix}.{key}")
    }
}

fn assign_table_positions(table: &mut Table, position: &mut usize) {
    for (_, item) in table.iter_mut() {
        if let Some(child) = item.as_table_mut() {
            child.set_position(*position);
            *position += 1;
            assign_table_positions(child, position);
        } else if let Some(array) = item.as_array_of_tables_mut() {
            for child in array.iter_mut() {
                child.set_position(*position);
                *position += 1;
                assign_table_positions(child, position);
            }
        }
    }
}
