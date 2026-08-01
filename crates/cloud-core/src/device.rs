use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct DeviceDescriptor {
    pub client_id: u64,
    pub machine_name: String,
    pub os_type: Option<i64>,
    pub device_type: Option<i64>,
}

static DEVICE_DESCRIPTOR: OnceLock<Mutex<Option<DeviceDescriptor>>> = OnceLock::new();

pub fn record_device_descriptor(descriptor: DeviceDescriptor) -> bool {
    let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() else {
        return false;
    };
    merge_device_descriptor(&mut current, descriptor)
}

pub fn device_descriptor() -> Option<DeviceDescriptor> {
    DEVICE_DESCRIPTOR
        .get_or_init(|| Mutex::new(None))
        .lock()
        .ok()
        .and_then(|current| current.clone())
}

pub fn restore_device_descriptor(descriptor: DeviceDescriptor) {
    if let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() {
        if current.is_none() {
            *current = Some(descriptor);
        }
    }
}

pub fn record_local_client_id(client_id: u64) {
    if client_id == 0 {
        return;
    }
    let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() else {
        return;
    };
    update_local_client_id(&mut current, client_id);
}

fn update_local_client_id(current: &mut Option<DeviceDescriptor>, client_id: u64) {
    if current
        .as_ref()
        .is_some_and(|descriptor| descriptor.client_id == client_id)
    {
        return;
    }
    *current = Some(DeviceDescriptor {
        client_id,
        machine_name: local_machine_name(),
        os_type: None,
        device_type: None,
    });
}

fn merge_device_descriptor(
    current: &mut Option<DeviceDescriptor>,
    mut incoming: DeviceDescriptor,
) -> bool {
    let previous = current.clone();
    if incoming.client_id == 0 {
        return false;
    }
    let has_machine_name =
        !incoming.machine_name.trim().is_empty() && incoming.machine_name != "unknown";
    let Some(existing) = current.as_mut() else {
        if !has_machine_name {
            incoming.machine_name = local_machine_name();
        }
        *current = Some(incoming);
        return *current != previous;
    };
    if existing.client_id != incoming.client_id {
        if !has_machine_name {
            incoming.machine_name = local_machine_name();
        }
        *existing = incoming;
        return *current != previous;
    }
    if has_machine_name {
        existing.machine_name = incoming.machine_name;
    }
    if incoming.os_type.is_some() {
        existing.os_type = incoming.os_type;
    }
    if incoming.device_type.is_some() {
        existing.device_type = incoming.device_type;
    }
    *current != previous
}

fn local_machine_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn updating_client_id_preserves_matching_descriptor() {
        let mut current = Some(DeviceDescriptor {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: Some(1),
            device_type: Some(2),
        });
        update_local_client_id(&mut current, 7);
        assert_eq!(current.as_ref().unwrap().machine_name, "deck");
        assert_eq!(current.as_ref().unwrap().os_type, Some(1));
    }

    #[test]
    fn updating_client_id_replaces_stale_descriptor() {
        let mut current = Some(DeviceDescriptor {
            client_id: 7,
            machine_name: "old".into(),
            os_type: Some(1),
            device_type: Some(2),
        });
        update_local_client_id(&mut current, 8);
        let current = current.unwrap();
        assert_eq!(current.client_id, 8);
        assert_eq!(current.os_type, None);
        assert_eq!(current.device_type, None);
    }

    #[test]
    fn merging_launch_metadata_preserves_known_fields() {
        let mut current = Some(DeviceDescriptor {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: Some(1),
            device_type: None,
        });
        assert!(merge_device_descriptor(
            &mut current,
            DeviceDescriptor {
                client_id: 7,
                machine_name: String::new(),
                os_type: None,
                device_type: Some(2),
            },
        ));
        let current = current.unwrap();
        assert_eq!(current.machine_name, "deck");
        assert_eq!(current.os_type, Some(1));
        assert_eq!(current.device_type, Some(2));
    }

    #[test]
    fn merging_identical_launch_metadata_is_not_a_context_change() {
        let descriptor = DeviceDescriptor {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: Some(1),
            device_type: Some(2),
        };
        let mut current = Some(descriptor.clone());
        assert!(!merge_device_descriptor(&mut current, descriptor));
    }
}
