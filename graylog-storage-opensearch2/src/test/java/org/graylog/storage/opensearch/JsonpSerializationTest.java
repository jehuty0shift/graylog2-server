package org.graylog.storage.opensearch;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.module.blackbird.BlackbirdModule;
import org.bson.types.ObjectId;
import org.graylog.storage.opensearch2.JsonpMessage;
import org.graylog2.indexer.IndexSet;
import org.graylog2.plugin.BackendVersion;
import org.graylog2.plugin.Message;
import org.graylog2.plugin.Version;
import org.graylog2.plugin.streams.Stream;
import org.graylog2.streams.StreamImpl;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.Mockito;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.Date;

public class JsonpSerializationTest {

    public static final String TEST_SOURCE = "Test source";
    public static final Instant TIMESTAMP = ZonedDateTime.of(2024,12,27,10,45,23,324123678, ZoneOffset.UTC).toInstant();
    public static final BackendVersion version = BackendVersion.fromOS(Version.from(2,0,0));

    public static final String STREAM_1_ID = "671f87a536d364e6548c468e";

    private ObjectMapper objMapper = new ObjectMapper().registerModule(new BlackbirdModule()).configure(JsonParser.Feature.STRICT_DUPLICATE_DETECTION,true);

    IndexSet indexSet;


    @Before
    public void setUp() {
        indexSet = Mockito.mock(IndexSet.class);
    }

    @Test
    public void jsonPSerializeMessage() throws Exception {



        Stream stream = new StreamImpl(new ObjectId(STREAM_1_ID), Collections.emptyMap(),Collections.emptyList(),Collections.emptySet(),indexSet);

        Message message = new Message("test message", TEST_SOURCE,TIMESTAMP);

        message.addField("request_http", "GET / 200");
        message.addField("client_ip", "192.168.54.23");
        message.addField("request_time_int",42);
        message.addStream(stream);


        JsonpMessage jsonMessage = new JsonpMessage(message, version);

        final String jsonString =jsonMessage.toJSonString();

        Assert.assertTrue(jsonString.contains("GET"));
        Assert.assertTrue(jsonString.contains("client_ip"));
        Assert.assertTrue(jsonString.contains("request_time_int"));
        Assert.assertTrue(jsonString.contains("42"));
        Assert.assertTrue(jsonString.contains("timestamp"));

        //ensure no duplicate + streams field
        Assert.assertTrue(objMapper.reader().readTree(jsonString).has("streams"));

        System.out.println(jsonString);



    }

}
