import strawberry
from graphql_api.queries.scan_queries import Query

schema = strawberry.Schema(query=Query)
