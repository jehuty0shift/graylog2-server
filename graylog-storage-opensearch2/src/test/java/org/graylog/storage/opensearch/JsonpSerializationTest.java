package org.graylog.storage.opensearch;

import org.graylog.storage.opensearch2.JsonpMessage;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Version;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;

public class JsonpSerializationTest {

    public static final String TEST_SOURCE = "source";
    public static final Instant TIMESTAMP = ZonedDateTime.of(2024,12,27,10,45,66,324123678, ZoneOffset.UTC).toInstant();
    public static final BackendVersion version = BackendVersion.fromOS(Version.from(2,0,0));


    @Test
    public void jsonPSerializeMessage() throws Exception {

        Message message = new Message("test message", TEST_SOURCE,TIMESTAMP);

        message.addField("request_http", "GET / 200");
        message.addField("client_ip", InetAddress.getByName("192.168.54.23"));
        message.addField("request_time_int",42);


        JsonpMessage jsonMessage = new JsonpMessage(message, version);


        System.out.println(jsonMessage.toJSonString());



    }

}
