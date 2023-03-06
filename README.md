# spring-authorization-server
Demo Authorization Server built with Spring (using H2 database)

Right URL to send request: 
http://localhost:9000/oauth2/authorize?response_type=code&client_id=taco-admin-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/taco-admin-client&scope=writeIngredients+deleteIngredients

To fetch the access token based on the authorization token returned by the above request, you should use a curl request with the following structure: 

curl localhost:9000/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=authorization_code" -d"redirect_uri=http://127.0.0.1:9090/login/oauth2/code/taco-admin-client" -d"code=q5_U1XNVIbIOZpej07uCGADZR_xcTvDvSNI7HSdbL0-J38w4doFQvz-v43X2LFUF4Tx8uGufvnftrXUIQWrxVt3C6fbbOIIuhnLBtFiRdbugmzGjYsn59X9D92n44K_I" -u taco-admin-client:secret
