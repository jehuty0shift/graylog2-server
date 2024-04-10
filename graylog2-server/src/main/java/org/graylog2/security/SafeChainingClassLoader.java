package org.graylog2.security;

import org.graylog2.shared.plugins.ChainingClassLoader;

import javax.inject.Inject;
import java.util.Locale;

public class SafeChainingClassLoader extends ClassLoader {
    private final ChainingClassLoader delegate;
    private final SafeClassesProvider scp;


    @Inject
    public SafeChainingClassLoader(ChainingClassLoader delegate, SafeClassesProvider scp) {
        this.delegate = delegate;
        this.scp = scp;
    }


    public Class<?> loadClassSafely(String name) throws ClassNotFoundException, UnauthorizedClassLoadingException {
        if (scp.isClassSafe(name)) {
            return delegate.loadClass(name);
        } else {
            throw new UnauthorizedClassLoadingException(String.format(Locale.ENGLISH, "this class \"%s\" is not allowed to be loaded", name));
        }
    }


}
