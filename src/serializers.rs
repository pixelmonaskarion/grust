use std::{fmt::Formatter, marker::PhantomData};

use protobuf::{MessageDyn, MessageFull};

pub fn serialize_proto<S: serde::Serializer>(
    m: &dyn MessageDyn,
    s: S,
) -> Result<S::Ok, S::Error> {
    s.serialize_str(&protobuf_json_mapping::print_to_string(m).map_err(|_| serde::ser::Error::custom("protobuf json serde failed"))?)
}

pub fn deserialize_proto<'de, E: MessageFull, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<E, D::Error> {
    struct DeserializeEnumVisitor<E: MessageFull>(PhantomData<E>);

    impl<'de, E: MessageFull> serde::de::Visitor<'de> for DeserializeEnumVisitor<E> {
        type Value = E;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            write!(formatter, "a json string representing the corrent protobuf type")
        }

        fn visit_str<R>(self, v: &str) -> Result<Self::Value, R>
        where
            R: serde::de::Error,
        {
            return protobuf_json_mapping::parse_from_str(v).map_err(|_| serde::de::Error::custom(format!("failed to parse json string {v}")))
        }
    }

    d.deserialize_any(DeserializeEnumVisitor(PhantomData))
}