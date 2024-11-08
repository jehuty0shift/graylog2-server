window.appConfig = {
  gl2ServerUrl: 'https://kube-1.dev.logs.ovh.com:30900/api/',
  gl2AppPathPrefix: '',
  rootTimeZone: 'Europe/Berlin',
  customUsername: 'Username',
  badgeText: 'ALPHA',
  webUIGuideLink: 'https://docs.ovh.com/gb/en/logs-data-platform/',
  webUICommunityLink: 'https://community.ovh.com/c/platform/data-platforms',
  oidcDefaultProvider : "ovh_eu",
  oidcProviders: ["keycloak","ovh_eu"],
  oidcProvidersDisplayName: ["Keycloak","OVHCloud EU IAM"],
  oidcClientIds: ["graylog","1664d6f1cd3c5caf"],
  oidcConnectUrls: [" http://kube-1.dev.logs.ovh.com:30980/realms/myrealm/","https://www.ovh.com/auth/"],
  httpExternalUri: 'https://gw2sdev-docker.ovh.net:22441',

};
