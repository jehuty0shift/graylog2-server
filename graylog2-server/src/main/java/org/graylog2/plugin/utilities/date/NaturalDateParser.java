/**
 * This file is part of Graylog.
 * <p>
 * Graylog is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * <p>
 * Graylog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p>
 * You should have received a copy of the GNU General Public License
 * along with Graylog.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog2.plugin.utilities.date;

import com.google.common.collect.Maps;
import com.joestelmach.natty.DateGroup;
import com.joestelmach.natty.Parser;
import org.graylog2.plugin.Tools;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class NaturalDateParser {
    public static final TimeZone UTC = TimeZone.getTimeZone("UTC");

    public Result parse(final String string) throws DateNotParsableException {
        Date from = null;
        Date to = null;

        final Parser parser = new Parser(UTC);
        final List<DateGroup> groups = parser.parse(string);
        if (!groups.isEmpty()) {
            final List<Date> dates = groups.get(0).getDates();
            Collections.sort(dates);

            if (dates.size() >= 1) {
                from = dates.get(0);
            }

            if (dates.size() >= 2) {
                to = dates.get(1);
            }
        } else {
            throw new DateNotParsableException("Unparsable date: " + string);
        }

        return new Result(from, to);
    }

    public static class Result {
        private final Instant from;
        private final Instant to;

        public Result(final Date from, final Date to) {
            if (from != null) {
                this.from = from.toInstant();
            } else {
                this.from = Instant.now();
            }

            if (to != null) {
                this.to = to.toInstant();
            } else {
                this.to = Instant.now();
            }
        }

        public Instant getFrom() {
            return from;
        }

        public Instant getTo() {
            return to;
        }

        public Map<String, String> asMap() {
            Map<String, String> result = Maps.newHashMap();

            result.put("from", dateFormat(getFrom()));
            result.put("to", dateFormat(getTo()));

            return result;
        }

        private String dateFormat(final Instant x) {
            return DateTimeFormatter.ofPattern(Tools.ES_DATE_FORMAT_NO_MS, Locale.ENGLISH).withZone(ZoneOffset.UTC).format(x);
        }
    }

    public static class DateNotParsableException extends Exception {
        public DateNotParsableException(String message) {
            super(message);
        }
    }

}
