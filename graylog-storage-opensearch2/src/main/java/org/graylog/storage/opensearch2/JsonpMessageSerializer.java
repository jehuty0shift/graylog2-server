package org.graylog.storage.opensearch2;

import jakarta.json.stream.JsonGenerator;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Version;
import org.opensearch.client.json.JsonpMapper;
import org.opensearch.client.json.JsonpSerializer;

public class JsonpMessageSerializer implements JsonpSerializer<Message> {

    private final BackendVersion version;

    public JsonpMessageSerializer() {
        this.version = BackendVersion.fromOS(Version.from(2,0,0));
    }
    @Override
    public void serialize(Message value, JsonGenerator generator, JsonpMapper mapper) {
        JsonpMessage jsonpMessage = new JsonpMessage(value,version);
        jsonpMessage.serialize(generator,mapper);
    }
}
