use prost::Message;
use vapor_forge_abi::{
    CMsgClientGamesPlayed, CMsgProtoBufHeader, ClientPersonaState, EncryptedAppTicketResponse,
    GetManifestRequestCodeRequest, PicsProductInfoRequest, PlayerGetUserStatsRequest,
    EMSG_CLIENT_PERSONA_STATE, EMSG_CLIENT_RICH_PRESENCE_UPLOAD, EMSG_ENCRYPTED_APPTICKET_RESPONSE,
    EMSG_GAMESPLAYED, EMSG_GAMESPLAYED_WITH_DATABLOB, EMSG_PICS_PRODUCT_INFO_REQUEST,
    EMSG_REQUEST_USERSTATS, EMSG_REQUEST_USERSTATS_RESPONSE, EMSG_SERVICE_METHOD_CALL_FROM_CLIENT,
    K_MSG_HDR_PROTO_FLAG,
};

pub const MANIFEST_REQUEST_CODE_JOB_NAME: &str = "ContentServerDirectory.GetManifestRequestCode#1";
pub const STATS_JOB_NAME: &str = "Player.GetUserStats#1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketDirection {
    Send,
    Recv,
}

impl PacketDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::Send => "send",
            Self::Recv => "recv",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketType {
    EncryptedTicket,
    Pics,
    ManifestCode,
    Stats,
    RichPresence,
    GamesPlayed,
    Persona,
    Unknown,
}

impl PacketType {
    pub fn label(self) -> &'static str {
        match self {
            Self::EncryptedTicket => "encrypted-ticket",
            Self::Pics => "pics",
            Self::ManifestCode => "manifest-code",
            Self::Stats => "stats",
            Self::RichPresence => "rich-presence",
            Self::GamesPlayed => "games-played",
            Self::Persona => "persona",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketChange {
    Unchanged,
    Dropped,
    Rewritten,
    Injected,
    Queued,
    DecodeFailed,
}

impl PacketChange {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Dropped => "dropped",
            Self::Rewritten => "rewritten",
            Self::Injected => "injected",
            Self::Queued => "queued",
            Self::DecodeFailed => "decode-failed",
        }
    }
}

#[derive(Clone, Debug)]
pub struct PacketSummary {
    pub id: u64,
    pub direction: PacketDirection,
    pub emsg_raw: Option<u32>,
    pub emsg: Option<u32>,
    pub proto: bool,
    pub packet_type: PacketType,
    pub app_ids: Vec<u32>,
    pub steamid: Option<u64>,
    pub job: Option<String>,
    pub eresult: Option<i32>,
    pub change: PacketChange,
    pub original_len: usize,
    pub final_len: Option<usize>,
    pub header_len: Option<usize>,
    pub body_len: Option<usize>,
    pub decode_error: Option<String>,
}

pub fn summarize_packet(
    id: u64,
    direction: PacketDirection,
    data: &[u8],
    change: PacketChange,
    final_len: Option<usize>,
) -> PacketSummary {
    let Some((emsg_raw, header_bytes, body_bytes)) = vapor_forge_abi::unpack_raw(data) else {
        return PacketSummary {
            id,
            direction,
            emsg_raw: None,
            emsg: None,
            proto: false,
            packet_type: PacketType::Unknown,
            app_ids: Vec::new(),
            steamid: None,
            job: None,
            eresult: None,
            change: PacketChange::DecodeFailed,
            original_len: data.len(),
            final_len,
            header_len: None,
            body_len: None,
            decode_error: Some("invalid Steam packet framing".to_owned()),
        };
    };

    let emsg = emsg_raw & !K_MSG_HDR_PROTO_FLAG;
    let proto = emsg_raw & K_MSG_HDR_PROTO_FLAG != 0;
    let mut summary = PacketSummary {
        id,
        direction,
        emsg_raw: Some(emsg_raw),
        emsg: Some(emsg),
        proto,
        packet_type: classify_by_emsg(emsg),
        app_ids: Vec::new(),
        steamid: None,
        job: None,
        eresult: None,
        change,
        original_len: data.len(),
        final_len,
        header_len: Some(header_bytes.len()),
        body_len: Some(body_bytes.len()),
        decode_error: None,
    };

    if proto {
        if let Ok(header) = CMsgProtoBufHeader::decode(header_bytes) {
            summary.steamid = header.steamid;
            summary.job = header.target_job_name.clone();
            if summary.packet_type == PacketType::Unknown {
                summary.packet_type = classify_by_job(header.target_job_name.as_deref());
            }
        }
    }

    match emsg {
        EMSG_ENCRYPTED_APPTICKET_RESPONSE => {
            if let Ok(resp) = EncryptedAppTicketResponse::decode(body_bytes) {
                push_app_id(&mut summary.app_ids, resp.app_id);
                summary.eresult = resp.eresult;
            }
        }
        EMSG_PICS_PRODUCT_INFO_REQUEST => {
            if let Ok(req) = PicsProductInfoRequest::decode(body_bytes) {
                for app in req.apps {
                    push_app_id(&mut summary.app_ids, app.appid);
                }
            }
        }
        EMSG_SERVICE_METHOD_CALL_FROM_CLIENT => {
            if summary.job.as_deref() == Some(MANIFEST_REQUEST_CODE_JOB_NAME) {
                if let Ok(req) = GetManifestRequestCodeRequest::decode(body_bytes) {
                    push_app_id(&mut summary.app_ids, req.app_id);
                }
            } else if summary.job.as_deref() == Some(STATS_JOB_NAME) {
                if let Ok(req) = PlayerGetUserStatsRequest::decode(body_bytes) {
                    push_app_id(&mut summary.app_ids, req.appid);
                    if summary.steamid.is_none() {
                        summary.steamid = req.steamid;
                    }
                }
            }
        }
        EMSG_GAMESPLAYED | EMSG_GAMESPLAYED_WITH_DATABLOB => {
            if let Ok(msg) = CMsgClientGamesPlayed::decode(body_bytes) {
                for game in msg.games_played {
                    push_app_id(&mut summary.app_ids, game.game_id.map(|id| id as u32));
                }
            }
        }
        EMSG_CLIENT_PERSONA_STATE => {
            if let Ok(msg) = ClientPersonaState::decode(body_bytes) {
                for friend in msg.friends {
                    push_app_id(&mut summary.app_ids, friend.game_played_app_id);
                }
            }
        }
        EMSG_REQUEST_USERSTATS => {
            if let Ok(req) = vapor_forge_abi::ClientGetUserStatsRequest::decode(body_bytes) {
                push_app_id(&mut summary.app_ids, req.game_id.map(|id| id as u32));
                if summary.steamid.is_none() {
                    summary.steamid = req.steam_id_for_user;
                }
            }
        }
        EMSG_REQUEST_USERSTATS_RESPONSE => {
            if let Ok(resp) = vapor_forge_abi::ClientGetUserStatsResponse::decode(body_bytes) {
                push_app_id(&mut summary.app_ids, resp.game_id.map(|id| id as u32));
                summary.eresult = resp.eresult;
            }
        }
        _ => {}
    }

    summary.app_ids.sort_unstable();
    summary.app_ids.dedup();
    summary
}

fn classify_by_emsg(emsg: u32) -> PacketType {
    match emsg {
        EMSG_ENCRYPTED_APPTICKET_RESPONSE => PacketType::EncryptedTicket,
        EMSG_PICS_PRODUCT_INFO_REQUEST => PacketType::Pics,
        EMSG_CLIENT_RICH_PRESENCE_UPLOAD => PacketType::RichPresence,
        EMSG_GAMESPLAYED | EMSG_GAMESPLAYED_WITH_DATABLOB => PacketType::GamesPlayed,
        EMSG_CLIENT_PERSONA_STATE => PacketType::Persona,
        EMSG_REQUEST_USERSTATS | EMSG_REQUEST_USERSTATS_RESPONSE => PacketType::Stats,
        _ => PacketType::Unknown,
    }
}

fn classify_by_job(job: Option<&str>) -> PacketType {
    match job {
        Some(MANIFEST_REQUEST_CODE_JOB_NAME) => PacketType::ManifestCode,
        Some(STATS_JOB_NAME) => PacketType::Stats,
        _ => PacketType::Unknown,
    }
}

fn push_app_id(out: &mut Vec<u32>, app_id: Option<u32>) {
    if let Some(app_id) = app_id {
        if app_id != 0 {
            out.push(app_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_invalid_framing() {
        let summary = summarize_packet(
            7,
            PacketDirection::Recv,
            b"bad",
            PacketChange::Unchanged,
            None,
        );

        assert_eq!(summary.id, 7);
        assert_eq!(summary.packet_type, PacketType::Unknown);
        assert_eq!(summary.change, PacketChange::DecodeFailed);
    }

    #[test]
    fn summarizes_manifest_request() {
        let header = CMsgProtoBufHeader {
            steamid: Some(76561198000000001),
            target_job_name: Some(MANIFEST_REQUEST_CODE_JOB_NAME.to_owned()),
            ..Default::default()
        };
        let body = GetManifestRequestCodeRequest {
            app_id: Some(480),
            depot_id: Some(481),
            manifest_id: Some(123),
        };
        let packet = vapor_forge_abi::assemble_raw(
            EMSG_SERVICE_METHOD_CALL_FROM_CLIENT | K_MSG_HDR_PROTO_FLAG,
            &header.encode_to_vec(),
            &body.encode_to_vec(),
        );

        let summary = summarize_packet(
            8,
            PacketDirection::Send,
            &packet,
            PacketChange::Dropped,
            Some(0),
        );

        assert_eq!(summary.packet_type, PacketType::ManifestCode);
        assert_eq!(summary.app_ids, vec![480]);
        assert_eq!(summary.steamid, header.steamid);
        assert_eq!(summary.job.as_deref(), Some(MANIFEST_REQUEST_CODE_JOB_NAME));
        assert_eq!(summary.change, PacketChange::Dropped);
        assert_eq!(summary.final_len, Some(0));
        assert_eq!(summary.header_len, Some(header.encoded_len()));
        assert_eq!(summary.body_len, Some(body.encoded_len()));
    }

    #[test]
    fn summarizes_service_stats_request_body() {
        let header = CMsgProtoBufHeader {
            target_job_name: Some(STATS_JOB_NAME.to_owned()),
            ..Default::default()
        };
        let body = PlayerGetUserStatsRequest {
            steamid: Some(76561198000000002),
            appid: Some(570),
            ..Default::default()
        };
        let packet = vapor_forge_abi::assemble_raw(
            EMSG_SERVICE_METHOD_CALL_FROM_CLIENT | K_MSG_HDR_PROTO_FLAG,
            &header.encode_to_vec(),
            &body.encode_to_vec(),
        );

        let summary = summarize_packet(
            9,
            PacketDirection::Send,
            &packet,
            PacketChange::Unchanged,
            None,
        );

        assert_eq!(summary.packet_type, PacketType::Stats);
        assert_eq!(summary.app_ids, vec![570]);
        assert_eq!(summary.steamid, body.steamid);
    }
}
