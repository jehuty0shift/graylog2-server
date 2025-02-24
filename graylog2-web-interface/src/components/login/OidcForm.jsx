import React, {useCallback, useEffect} from "react";
import {useAuth} from "react-oidc-context";
import {Button} from 'components/graylog';
import CombinedProvider from "../../injection/CombinedProvider";
import history from 'util/History';
import Routes from 'routing/Routes';
import StoreProvider from "../../injection/StoreProvider";

const {SessionActions} = CombinedProvider.get('Session');
const SessionStore = StoreProvider.getStore('Session');


function OidcForm({idProvider, idProviderDisplayName, onErrorChange}) {

  const AUTO_LOGIN_QUERY_PARAM = "auto_login";
  const auth = useAuth();

  const {isAuthenticated} = auth;
  const queryParams = new URLSearchParams(window.location.search);
  const targetRedirect = { navigateTo: window.location};

  const onHandleClick = () => {
    auth.signinRedirect({ state: targetRedirect }).catch(() => onErrorChange(`Error during sign-in to ${idProviderDisplayName}`));
  };

  const loginUser = useCallback(async () => {

    onErrorChange();
    if (auth.isAuthenticated && !SessionStore.isLoggedIn()) {

      try {
        await SessionActions.loginUrl('/system/oidc/login', {
          access_token: auth.user?.access_token,
          id_token: auth.user?.id_token,
          expires_at: auth.user?.expires_at,
          idProvider: idProvider
        });
        await auth.removeUser();
        history.push(auth.user?.state.navigateTo);
      } catch (error) {
        console.log(error);
        onErrorChange("Unexpected Error during Login");
      }
    }
  }, [auth]);

  const extractId = (urn) => {
    return urn.split(':').pop();
  };

  useEffect(() => {
    if (auth.isAuthenticated) {
      loginUser().catch(() => {
        onErrorChange("Unexpected Error during Login");
      });
    }

    if (queryParams.has(AUTO_LOGIN_QUERY_PARAM)) {
      if (queryParams.get(AUTO_LOGIN_QUERY_PARAM) === "true") {
        onHandleClick();
      }
    }
  }, [isAuthenticated]);

  switch (auth.activeNavigator) {
    case "signinSilent":
      return <div>Signing you in...</div>;
    case "signoutRedirect":
      return <div>Signing you out...</div>;
  }

  if (auth.isLoading) {
    return <div>Loading...</div>;
  }

  if (auth.error) {
    onErrorChange(`Error during authentication: ${auth.error.message}.\nPlease refresh the page or contact the Support if it persists`);
    return <div>Unexpected Error... {auth.error.message}</div>;
  }

  if (auth.isAuthenticated) {

    return (<div>
      <p>Hello {extractId(auth.user?.profile.sub)}, Wait for redirection or click on the button to log out.{" "}</p>
      <Button onClick={() => auth.removeUser()}>Log out</Button>
    </div>);
  }

  return (<Button
    onClick={onHandleClick}
    bsStyle="info">
    Log in with {idProviderDisplayName}
  </Button>);


}


export default OidcForm;
