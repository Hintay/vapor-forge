use rusqlite::{params, OptionalExtension};

use crate::{DeviceDescriptor, Outbox, OutboxError};

impl Outbox {
    pub fn load_device_descriptor(&self) -> Result<Option<DeviceDescriptor>, OutboxError> {
        self.connection
            .query_row(
                "SELECT client_id, machine_name, os_type, device_type
                 FROM device_identity WHERE singleton = 1",
                [],
                |row| {
                    let client_id: String = row.get(0)?;
                    Ok(DeviceDescriptor {
                        client_id: client_id.parse().map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                0,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        })?,
                        machine_name: row.get(1)?,
                        os_type: row.get(2)?,
                        device_type: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn store_device_descriptor(
        &self,
        descriptor: &DeviceDescriptor,
        now: i64,
    ) -> Result<(), OutboxError> {
        self.connection.execute(
            "INSERT INTO device_identity (
                singleton, client_id, machine_name, os_type, device_type, updated_at
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(singleton) DO UPDATE SET
                client_id = excluded.client_id,
                machine_name = excluded.machine_name,
                os_type = excluded.os_type,
                device_type = excluded.device_type,
                updated_at = excluded.updated_at
             WHERE client_id != excluded.client_id
                OR machine_name != excluded.machine_name
                OR os_type IS NOT excluded.os_type
                OR device_type IS NOT excluded.device_type",
            params![
                descriptor.client_id.to_string(),
                descriptor.machine_name,
                descriptor.os_type,
                descriptor.device_type,
                now,
            ],
        )?;
        Ok(())
    }
}
