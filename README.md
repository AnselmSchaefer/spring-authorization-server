# spring-authorization-server
Demo Authorization Server built with Spring (using H2 database)

Right URL to send request: 
http://localhost:9000/oauth2/authorize?response_type=code&client_id=taco-admin-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/taco-admin-client&scope=writeIngredients+deleteIngredients

The old version provided a site where the scope could be selected. Not provided in this example.
