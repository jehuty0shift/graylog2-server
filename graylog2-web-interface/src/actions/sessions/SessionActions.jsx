import Reflux from 'reflux';

const SessionActions = Reflux.createActions({
  login: { asyncResult: true },
  loginUrl: { asyncResult: true},
  logout: { asyncResult: true },
  validate: { asyncResult: true },
});

export default SessionActions;
