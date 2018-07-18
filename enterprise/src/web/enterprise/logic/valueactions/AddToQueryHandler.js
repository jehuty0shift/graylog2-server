import { QueriesActions } from 'enterprise/stores/QueriesStore';
import QueryManipulationHandler from './QueryManipulationHandler';

export default class AddToQueryHandler extends QueryManipulationHandler {
  formatNewQuery = (oldQuery, field, value) => {
    const fieldPredicate = `${field}:${this.escape(value)}`;

    return this.addToQuery(oldQuery, fieldPredicate);
  };

  handle = (queryId, field, value) => {
    const query = this.queries.get(queryId);
    const oldQuery = query.query.query_string;
    const newQuery = this.formatNewQuery(oldQuery, field, value);
    QueriesActions.query(queryId, newQuery);
  };
}
