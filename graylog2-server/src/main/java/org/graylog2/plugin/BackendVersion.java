package org.graylog2.plugin;

import java.io.Serializable;
import java.util.Locale;
import java.util.Objects;

public class BackendVersion implements Comparable<BackendVersion>, Serializable {

    public enum SearchEngine {
        ELASTICSEARCH,
        OPENSEARCH
    }

    private static final long serialVersionUID = 1L;
    private final Version version;
    private final SearchEngine engine;

    private BackendVersion(SearchEngine engine, Version version) {
        this.engine = engine;
        this.version = version;
    }


    public static BackendVersion from(SearchEngine engine, Version version) {
        return new BackendVersion(engine, version);
    }

    public static BackendVersion from(String distribution, Version version) {
        if ("opensearch".equals(distribution.toLowerCase(Locale.ENGLISH))) {
            return new BackendVersion(SearchEngine.OPENSEARCH, version);
        } else {
            return new BackendVersion(SearchEngine.ELASTICSEARCH, version);
        }
    }

    public static BackendVersion fromES(Version version) {
        return new BackendVersion(SearchEngine.ELASTICSEARCH, version);
    }

    public static BackendVersion fromOS(Version version) {
        return new BackendVersion(SearchEngine.OPENSEARCH, version);
    }

    public SearchEngine getSearchEngine() {
        return engine;
    }

    public Version getVersion() {
        return version;
    }

    public int getMajorVersion() {
        return version.getVersion().getMajorVersion();
    }


    @Override
    public String toString() {
        return "BackendVersion{" +
                "version=" + version.toString() +
                ", engine=" + engine.toString() +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        BackendVersion that = (BackendVersion) o;
        return version.equals(that.version) && engine == that.engine;
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, engine);
    }

    @Override
    public int compareTo(BackendVersion o) {
        if (engine.equals(o.engine)) {
            return version.compareTo(o.version);
        } else {
            return engine.equals(SearchEngine.OPENSEARCH)?1:-1;
        }
    }
}
