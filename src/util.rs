use crate::protos::{authentication::ConfigVersion, conversations::MediaFormats};

pub fn config_version() -> ConfigVersion {
    ConfigVersion {
        Year: 2024,
        Month: 12,
        Day: 9,
        V1: 4,
        V2: 6,
        ..Default::default()
    }
}

pub fn generate_tmp_id() -> String {
	let x = rand::random::<i64>() % 1000000000000;
	return format!("tmp_{x}");
}

pub fn mime_to_media_type(mime: &str) -> Option<(&'static str, MediaFormats)> {
    match mime {
        "image/jpeg" => Some(("jpeg".into(), MediaFormats::IMAGE_JPEG)),
        "image/jpg" => Some(("jpg".into(), MediaFormats::IMAGE_JPG)),
        "image/png" => Some(("png".into(), MediaFormats::IMAGE_PNG)),
        "image/gif" => Some(("gif".into(), MediaFormats::IMAGE_GIF)),
        "image/wbmp" => Some(("wbmp".into(), MediaFormats::IMAGE_WBMP)),
        "image/bmp" => Some(("bmp".into(), MediaFormats::IMAGE_X_MS_BMP)),
        "image/x-ms-bmp" => Some(("bmp".into(), MediaFormats::IMAGE_X_MS_BMP)),

        "video/mp4" => Some(("mp4".into(), MediaFormats::VIDEO_MP4)),
        "video/3gpp2" => Some(("3gpp2".into(), MediaFormats::VIDEO_3G2)),
        "video/3gpp" => Some(("3gpp".into(), MediaFormats::VIDEO_3GPP)),
        "video/webm" => Some(("webm".into(), MediaFormats::VIDEO_WEBM)),
        "video/x-matroska" => Some(("mkv".into(), MediaFormats::VIDEO_MKV)),

        "audio/aac" => Some(("aac".into(), MediaFormats::AUDIO_AAC)),
        "audio/amr" => Some(("amr".into(), MediaFormats::AUDIO_AMR)),
        "audio/mp3" => Some(("mp3".into(), MediaFormats::AUDIO_MP3)),
        "audio/mpeg" => Some(("mpeg".into(), MediaFormats::AUDIO_MPEG)),
        "audio/mpg" => Some(("mpg".into(), MediaFormats::AUDIO_MPG)),
        "audio/mp4" => Some(("mp4".into(), MediaFormats::AUDIO_MP4)),
        "audio/mp4-latm" => Some(("latm".into(), MediaFormats::AUDIO_MP4_LATM)),
        "audio/3gpp" => Some(("3gpp".into(), MediaFormats::AUDIO_3GPP)),
        "audio/ogg" => Some(("ogg".into(), MediaFormats::AUDIO_OGG)),

        "text/vcard" => Some(("vcard".into(), MediaFormats::TEXT_VCARD)),
        "application/pdf" => Some(("pdf".into(), MediaFormats::APP_PDF)),
        "text/plain" => Some(("txt".into(), MediaFormats::APP_TXT)),
        "text/html" => Some(("html".into(), MediaFormats::APP_HTML)),
        "application/msword" => Some(("doc".into(), MediaFormats::APP_DOC)),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document" => Some(("docx".into(), MediaFormats::APP_DOCX)),
        "application/vnd.openxmlformats-officedocument.presentationml.presentation" => Some(("pptx".into(), MediaFormats::APP_PPTX)),
        "application/vnd.ms-powerpoint" => Some(("ppt".into(), MediaFormats::APP_PPT)),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" => Some(("xlsx".into(), MediaFormats::APP_XLSX)),
        "application/vnd.ms-excel" => Some(("xls".into(), MediaFormats::APP_XLS)),
        "application/vnd.android.package-archive" => Some(("apk".into(), MediaFormats::APP_APK)),
        "application/zip" => Some(("zip".into(), MediaFormats::APP_ZIP)),
        "application/java-archive" => Some(("jar".into(), MediaFormats::APP_JAR)),
        "text/x-calendar" => Some(("vcs".into(), MediaFormats::CAL_TEXT_VCALENDAR)),
        "text/calendar" => Some(("ics".into(), MediaFormats::CAL_TEXT_CALENDAR)),

        "image" => Some(("".into(), MediaFormats::IMAGE_UNSPECIFIED)),
        "video" => Some(("".into(), MediaFormats::VIDEO_UNSPECIFIED)),
        "audio" => Some(("".into(), MediaFormats::AUDIO_UNSPECIFIED)),
        "application" => Some(("".into(), MediaFormats::APP_UNSPECIFIED)),
        "text" => Some(("".into(), MediaFormats::APP_TXT)),
        _ => None
    }
}