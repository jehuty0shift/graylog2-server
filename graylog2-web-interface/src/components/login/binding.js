import {PluginManifest, PluginStore} from "graylog-web-plugin/plugin";
import LoginSelector from './LoginSelector'

PluginStore.register(new PluginManifest({}, {
  loginProviderType: [{
    type: "LoginSelector",
    formComponent: LoginSelector,
  }
  ]
}));
