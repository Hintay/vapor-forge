use std::str::FromStr;

use toml_edit::{DocumentMut, Table};

use crate::RuntimeConfig;

pub const CONFIG_TEMPLATE: &str = include_str!("../../../res/config.default.toml");

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
        let document = parse_document(&text)?;
        let template_text = prune_commented_section_examples(CONFIG_TEMPLATE, document.as_table());
        let mut template = parse_document(&template_text)?;

        merge_user_values_into_template(template.as_table_mut(), document.as_table());
        let mut position = 0;
        assign_table_positions(template.as_table_mut(), &mut position);

        let synced = template.to_string();
        if synced == text {
            return Ok(false);
        }
        std::fs::write(path, synced)?;
        Ok(true)
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
        let should_prune = parse_commented_section_header(line)
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
