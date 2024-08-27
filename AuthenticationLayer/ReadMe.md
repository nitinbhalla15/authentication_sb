# JWT Authentication using JAVA - SPRING BOOT - SPRING SECURITY

* This Project uses in memory db h2 , if wants to switch to separate db server needs to change application yaml 
* Configure the end points in SecurityConfig.java which needs to be white listed 
* Intercepting of requests is done by implementing custom filter in front of filters provided by spring security

### Basic flow of application :
    
     White listed APIs will not be authenticated and will be bypassed by custom filter to be proccessed.
        

Secure API end points will follow this flow :
        
req ->  custom filter -> (if auth not passed -> pass req to 
other filter -> other filter will send error as 403) -> if auth token was passed and is parsed to the correct subject i.e email , user detail service will find the user and validate the details -> req then goes to auth manager -> auth manager decides which auth provider will be used to authenticate the req -> req goes to the correct auth provider and get quthenticated accordingly with the response to client