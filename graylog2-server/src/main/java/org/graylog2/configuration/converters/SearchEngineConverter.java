package org.graylog2.configuration.converters;

import com.github.joschi.jadconfig.Converter;
import org.graylog2.plugin.BackendVersion;

import java.util.Locale;

public class SearchEngineConverter implements Converter<BackendVersion.SearchEngine> {


    @Override
    public BackendVersion.SearchEngine convertFrom(String searchEngine) {
        if ("opensearch".equals(searchEngine.toLowerCase(Locale.ENGLISH))) {
            return BackendVersion.SearchEngine.OPENSEARCH;
        } else {
            return BackendVersion.SearchEngine.ELASTICSEARCH;
        }
    }

    @Override
    public String convertTo(BackendVersion.SearchEngine searchEngine) {
        return searchEngine.toString();
    }
}
