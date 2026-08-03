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
    if descriptor.client_id == 0 {
        return false;
    }
    let Ok(mut current) = DEVICE_DESCRIPTOR.get_or_init(|| Mutex::new(None)).lock() else {
        return false;
    };
    replace_device_descriptor(&mut current, descriptor)
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

pub fn record_local_client_id(client_id: u64) -> bool {
    record_device_descriptor(DeviceDescriptor {
        client_id,
        machine_name: String::new(),
        os_type: None,
        device_type: None,
    })
}

fn replace_device_descriptor(
    current: &mut Option<DeviceDescriptor>,
    descriptor: DeviceDescriptor,
) -> bool {
    if current.as_ref() == Some(&descriptor) {
        return false;
    }
    *current = Some(descriptor);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_id_only_replaces_matching_descriptor() {
        let mut current = Some(DeviceDescriptor {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: Some(1),
            device_type: Some(2),
        });
        assert!(replace_device_descriptor(
            &mut current,
            DeviceDescriptor {
                client_id: 7,
                machine_name: String::new(),
                os_type: None,
                device_type: None,
            }
        ));
        let current = current.unwrap();
        assert!(current.machine_name.is_empty());
        assert_eq!(current.os_type, None);
        assert_eq!(current.device_type, None);
    }

    #[test]
    fn current_login_replaces_restored_descriptor() {
        let mut current = Some(DeviceDescriptor {
            client_id: 7,
            machine_name: "old".into(),
            os_type: Some(1),
            device_type: Some(2),
        });
        assert!(replace_device_descriptor(
            &mut current,
            DeviceDescriptor {
                client_id: 8,
                machine_name: "current".into(),
                os_type: None,
                device_type: None,
            }
        ));
        let current = current.unwrap();
        assert_eq!(current.client_id, 8);
        assert_eq!(current.machine_name, "current");
        assert_eq!(current.os_type, None);
        assert_eq!(current.device_type, None);
    }

    #[test]
    fn identical_login_metadata_is_not_a_context_change() {
        let descriptor = DeviceDescriptor {
            client_id: 7,
            machine_name: "deck".into(),
            os_type: Some(1),
            device_type: Some(2),
        };
        let mut current = Some(descriptor.clone());
        assert!(!replace_device_descriptor(&mut current, descriptor));
    }
}
