package org.graylog.storage.opensearch2;

import com.google.auto.value.AutoValue;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@AutoValue
abstract class ParsedOpensearchException {
    private static final Pattern exceptionPattern = Pattern
            .compile("ElasticsearchException\\[Elasticsearch exception \\[type=(?<type>[\\w_]+), (?:reason=(?<reason>.+?)(\\]+;|\\]$))");

    abstract String type();
    abstract String reason();

    static ParsedOpensearchException create(String type, String reason) {
        return new AutoValue_ParsedOpensearchException(type, reason);
    }

    static ParsedOpensearchException from(String s) {
        final Matcher matcher = exceptionPattern.matcher(s);
        if (matcher.find()) {
            final String type = matcher.group("type");
            final String reason = matcher.group("reason");

            return create(type, reason);
        }

        throw new IllegalArgumentException("Unable to parse Elasticsearch exception: " + s);
    }
}
