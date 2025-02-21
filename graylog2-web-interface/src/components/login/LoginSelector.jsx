import React, {useCallback, useState} from 'react';
import PropTypes from 'prop-types';
import {Input} from 'components/bootstrap';
import {Select} from 'components/common';
import {AuthProvider} from 'react-oidc-context';
import LoginForm from './LoginForm';
import OidcForm from './OidcForm';
import AppConfig from 'util/AppConfig';
import {Log} from 'oidc-client-ts';
import history from "../../util/History";
import Routes from "../../routing/Routes";

const LoginSelector = ({onErrorChange}) => {

  const LDP_BUILT_INT = "ldp";
  const ID_PROVIDER_PARAM = "idProvider";
  const idProviderExtractor = /\/oidc\/login\/(.*)\/redirect_uri.*/;
  const PARAMETER_TEST = "test=toto";

  const queryParams = new URLSearchParams(window.location.search);


  const extractIdProvider = () => {
    if (window.location.pathname.startsWith('/oidc/login')) {
      const arr = idProviderExtractor.exec(window.location.pathname);
      if (AppConfig.oidcProviders()[arr[1]]) {
        return arr[1];
      }
    }

    if (queryParams.has(ID_PROVIDER_PARAM)) {
      const urlIdProvider = queryParams.get(ID_PROVIDER_PARAM);
      if (AppConfig.oidcProviders()[urlIdProvider] !== undefined || urlIdProvider === LDP_BUILT_INT) {
        return urlIdProvider;
      }
    }

    return AppConfig.oidcDefaultProvider();
  };


  const [idProvider, setIdProvider] = useState(extractIdProvider);

  Log.setLogger(console);

  const loginOptions = useCallback(() => {
    const oidcProviders = AppConfig.oidcProviders();
    const options = [{value: LDP_BUILT_INT, label: 'Legacy username/password'}];

    Object.entries(oidcProviders).forEach(([key, value]) => {
      options.push({value: key, label: value.oidcDisplayName});
    });

    return options;
  }, []);


  const handleSelectChange = (selected) => {
    setIdProvider(selected);
  };

  const renderIdPForm = () => {

    const appOidcProviders = AppConfig.oidcProviders();

    let currentIdProvider = idProvider;
    if (window.location.pathname.startsWith('/oidc/login')) {
      const arr = idProviderExtractor.exec(window.location.pathname);
      if (arr.size === 0) {
        history.push(Routes.STARTPAGE);
      }
      if (appOidcProviders[arr[1]]) {
        currentIdProvider = arr[1];
      }
    }
    if (currentIdProvider === 'ldp' || !appOidcProviders[currentIdProvider]) {
      return <LoginForm onErrorChange={onErrorChange}/>;
    } else {
      const oidcProvider = appOidcProviders[idProvider];
      const httpUrlExternalUri = AppConfig.httpExternalUri().replace(/\/$/, '');
      const httpApiUri = AppConfig.gl2ServerUrl();
      const oidcConfigProvider = () => {
        if (idProvider.includes("ovh")) {
          return {
            authority: oidcProvider.oidcConnectUrl,
            extraHeaders: {
              "X-Requested-By": "XMLHttpRequest",
              "X-Requested-With": "XMLHttpRequest"
            },
            metadata: {
              issuer: oidcProvider.oidcConnectUrl,
              authorization_endpoint: oidcProvider.oidcConnectUrl + `oauth2/authorize`,
              token_endpoint: `${httpApiUri}system/oidc/${idProvider}/token`,
              userinfo_endpoint: oidcProvider.oidcConnectUrl + `oauth2/user`,
              revocation_endpoint: oidcProvider.oidcConnectUrl + `oauth2/revoke`,
              end_user_endpoint: oidcProvider.oidcConnectUrl + `oauth2/revoke`,
            },
            client_id: oidcProvider.oidcClientId,
            redirect_uri: `${httpUrlExternalUri}/oidc/login/${idProvider}/redirect_uri`,
            onSigninCallback: (_user) => {
              window.history.replaceState({}, document.title, window.location.pathname);
            },
            scope: "openid",
          }
        } else {
          return {
            authority: oidcProvider.oidcConnectUrl,
            client_id: oidcProvider.oidcClientId,
            redirect_uri: `${httpUrlExternalUri}/oidc/login/${idProvider}/redirect_uri`,
            onSigninCallback: (_user) => {
              window.history.replaceState({}, document.title, window.location.pathname);
            },
          }
        }
      };

      const oidcConfig = oidcConfigProvider();

      return (
        <AuthProvider {...oidcConfig} key={idProvider}>
          <OidcForm idProvider={currentIdProvider} idProviderDisplayName={oidcProvider.oidcDisplayName}
                    onErrorChange={onErrorChange}/>
        </AuthProvider>
      );
    }
  };

  const appOidcProviders = AppConfig.oidcProviders();

  if (Object.keys(appOidcProviders).length === 0 && appOidcProviders.constructor === Object) {
    return <LoginForm onErrorChange={onErrorChange}/>;
  } else {
    return (
      <span>
      <Input
        id="login-selector"
        label="Select your Login provider"
        help="Select the login Provider to create a Graylog session"
      >
        <Select
          placeholder="Select a Login provider"
          options={loginOptions()}
          onChange={handleSelectChange}
          value={idProvider}
        />
      </Input>
        {renderIdPForm()}
    </span>
    );
  }
};

LoginSelector.propTypes = {
  onErrorChange: PropTypes.func.isRequired,
};

export default LoginSelector;
