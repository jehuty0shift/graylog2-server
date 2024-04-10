package org.graylog2.security;

import com.mongodb.lang.NonNull;
import org.graylog2.Configuration;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import java.util.Objects;
import java.util.Set;


@Singleton
public class SafeClassesProvider {

    private Set<String> classPrefixes;

    public static SafeClassesProvider allLdpInternal() {
        return new SafeClassesProvider(Set.of("org.graylog.", "org.graylog2.","thot.ovh","com.wizecore","com.ovh","org.ovh"));
    }

    @Inject
    public SafeClassesProvider(@Named(Configuration.SAFE_CLASSES) @NonNull final Set<String> classPrefixes) {
        this.classPrefixes = Objects.requireNonNull(classPrefixes);
    }


    public boolean isClassSafe(final String classname) {
        return classPrefixes.stream().anyMatch(classname::startsWith);
    }



}
