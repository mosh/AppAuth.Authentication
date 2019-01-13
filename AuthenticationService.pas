namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation,RemObjects.Elements.RTL;

type


  AuthenticationService = public class(IOIDAuthStateChangeDelegate,IOIDAuthStateErrorDelegate)

  private
    _authState:OIDAuthState;

    class _service : AuthenticationService;

    method authState(state: OIDAuthState) didEncounterAuthorizationError(error: NSError);
    begin
      NSLog('Received authorization error: %@', error);
    end;

    method authState(state: OIDAuthState) didEncounterTransientError(error: NSError);
    begin
      NSLog('Received transient error: %@', error);
    end;

    method cancel;
    begin
    end;

    method saveState(state:OIDAuthState);
    begin
      var archivedAuthState: NSData := NSKeyedArchiver.archivedDataWithRootObject(state);
      NSUserDefaults.standardUserDefaults().setObject(archivedAuthState) forKey(StateKey);
      NSUserDefaults.standardUserDefaults().synchronize();
    end;


    method didChangeState(state:not nullable OIDAuthState);
    begin

      saveState(state);

      var info := getUserInfo;
      &delegate:stateChanged(info);

    end;

    method get_Expired:Boolean;
    begin

      if(not assigned(AuthState)) or ((assigned(AuthState)) and (not assigned(AuthState.lastTokenResponse))) then
      begin
        exit false;
      end;

      var expiryDate := DateTime(AuthState.lastTokenResponse.accessTokenExpirationDate);

      var currentTime := new DateTime;

      if(expiryDate < currentTime)then
      begin
        exit true;
      end;

      exit false;
    end;

    method get_Authorized:Boolean;
    begin
      var _authorized := iif(assigned(AuthState),AuthState.isAuthorized(),false);
      if(not _authorized)then
      begin
        NSLog('AuthenticationService: Not Authorized');
      end;
      exit _authorized;
    end;


    method get_AuthState:OIDAuthState;
    begin
      exit _authState;
    end;

    method set_AuthState(value:OIDAuthState);
    begin
      if(assigned(value))then
      begin
        value.stateChangeDelegate := self;
      end;
      _authState := value;

      var info:UserInfo := nil;

      if(assigned(_authState))then
      begin
        info := getUserInfo;
      end;

      saveState(value);

      &delegate:stateChanged(info);
    end;

    method get_AccessToken:String;
    begin
      var _accessToken := iif(Authorized,AuthState.lastTokenResponse.accessToken,'');
      NSLog('AuthenticationService AccessToken [%@]',_accessToken);
      exit _accessToken;
    end;

    class method performTokenRequest(request: OIDTokenRequest) callback(callback: OIDTokenCallback);
    begin
      var urlRequest: NSURLRequest := request.URLRequest();
      var session : NSURLSession := NSURLSession.sharedSession;

      var dataTask := session.dataTaskWithRequest(urlRequest) completionHandler((data, response, error) ->
        begin
          if(assigned(error))then
          begin
            var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.NetworkError) underlyingError(error) description(nil);
            callback(nil,returnedError);
          end
          else
          begin
            var httpUrlResponse: NSHTTPURLResponse := NSHTTPURLResponse(response);

            if(httpUrlResponse.statusCode <> 200) then
            begin

              // A server error occurred.
              var serverError : NSError := OIDErrorUtilities.HTTPErrorWithHTTPResponse(httpUrlResponse) data(data);

              // HTTP 400 may indicate an RFC6749 Section 5.2 error response, checks for that
              if (httpUrlResponse.statusCode = 400) then
              begin
                var jsonDeserializationError:NSError;

                var json := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonDeserializationError);

                // if the HTTP 400 response parses as JSON and has an 'error' key, it's an OAuth error
                // these errors are special as they indicate a problem with the authorization grant
                if (json[OIDOAuthErrorFieldError]) then
                begin
                  var oAuthError:NSError := OIDErrorUtilities.OAuthErrorWithDomain(OIDOAuthTokenErrorDomain) OAuthResponse(json) underlyingError(serverError);
                  callback(nil, oAuthError);
                  exit;
                end;
              end;

              // not an OAuth error, just a generic server error
              var returnedError:NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.ServerError) underlyingError(serverError) description(nil);
              callback(nil,returnedError);
              exit;
            end
            else
            begin

              var jsonDeserializationError:NSError;

              var json := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonDeserializationError);

              if(assigned(jsonDeserializationError))then
              begin
                var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.JSONDeserializationError) underlyingError(jsonDeserializationError) description(nil);
                callback(nil, returnedError);
              end
              else
              begin
                var tokenResponse := new OIDTokenResponse withRequest(request) parameters(json);

                if(not assigned(tokenResponse))then
                begin
                  var returnedError: NSError := OIDErrorUtilities.errorWithCode(OIDErrorCode.TokenResponseConstructionError) underlyingError(jsonDeserializationError) description(nil);
                  callback(nil, returnedError);
                end
                else
                begin
                  callback(tokenResponse,nil);
                end;
              end;
            end;
          end;

        end);

      dataTask.resume;
    end;

    method fillUserInfo(jsonDictionaryOrArray:id):UserInfo;
    begin
      var info:=new UserInfo;
      info.FamilyName := jsonDictionaryOrArray['family_name'];
      info.Gender := jsonDictionaryOrArray['gender'];
      info.GivenName := jsonDictionaryOrArray['given_name'];
      info.Locale := jsonDictionaryOrArray['locale'];
      info.Name := jsonDictionaryOrArray['name'];
      info.Picture := jsonDictionaryOrArray['picture'];
      info.Email := jsonDictionaryOrArray['email'];
      exit info;
    end;

    method processResponse(data:NSData; httpResponse: NSHTTPURLResponse;taskError:NSError):UserInfo;
    begin
      var info:UserInfo:=nil;
      var jsonError: NSError;

      var jsonDictionaryOrArray: id := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonError);

      if httpResponse.statusCode ≠ 200 then
      begin
        var responseText: NSString := new NSString WithData(data) encoding(NSStringEncoding.NSUTF8StringEncoding);

        if httpResponse.statusCode = 401 then
        begin
          var oauthError: NSError := OIDErrorUtilities.resourceServerAuthorizationErrorWithCode(0) errorResponse(jsonDictionaryOrArray) underlyingError(taskError);
          AuthState.updateWithAuthorizationError(oauthError);
          NSLog('Authorization Error (%@). Response: %@', oauthError, responseText);
        end
        else
        begin
          NSLog('HTTP: %d. Response: %@', Integer(httpResponse.statusCode), responseText);
        end;

        exit;
      end;

      info := fillUserInfo(jsonDictionaryOrArray);

      NSLog('Success: %@', jsonDictionaryOrArray);

      exit info;
    end;



  public

    property AuthState:OIDAuthState read get_AuthState write set_AuthState;
    property Expired:Boolean read get_Expired;
    property Authorized:Boolean read get_Authorized;

    method refresh;
    begin

      //if(Expired)then
      if(assigned(AuthState))then
      begin

        NSLog('current expiry %@',AuthState.lastTokenResponse.accessTokenExpirationDate);

        var request :OIDTokenRequest := AuthState.tokenRefreshRequest;

        if(assigned(request))then
        begin

          var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method
            begin

              var semaphore := dispatch_semaphore_create(0);

              /*OIDAuthorizationService.*/performTokenRequest(request) callback(method (tokenResponse: AppAuth.OIDTokenResponse; error: NSError)
                begin
                  if(assigned(tokenResponse))then
                  begin
                    NSLog('new expiry %@',tokenResponse.accessTokenExpirationDate);
                  end
                  else
                  begin
                    NSLog('%@','tokenResponse not assigned');
                  end;

                  AuthState.updateWithTokenResponse(tokenResponse) error(error);
                  dispatch_semaphore_signal(semaphore);
                end);

              dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

            end);

          var workerQueue := new NSOperationQueue();
          workerQueue.addOperations([outerExecutionBlock]) waitUntilFinished(true);


        end;
      end;
    end;

    method getUserInfo:UserInfo;
    begin
      var userinfoEndpoint: NSURL := AuthState.lastAuthorizationResponse.request.configuration.discoveryDocument.userinfoEndpoint;
      var info:UserInfo := nil;

      if not assigned(userinfoEndpoint) then
      begin
        raise new NSException withName('') reason('Userinfo endpoint not declared in discovery document') userInfo(nil);
      end;

      var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method begin

        var semaphore := dispatch_semaphore_create(0);

        var request: NSMutableURLRequest := NSMutableURLRequest.requestWithURL(userinfoEndpoint);
        var authorizationHeaderValue: NSString := NSString.stringWithFormat('Bearer %@', AccessToken);
        request.addValue(authorizationHeaderValue) forHTTPHeaderField('Authorization');
        var configuration: NSURLSessionConfiguration := NSURLSessionConfiguration.defaultSessionConfiguration();
        var session: NSURLSession := NSURLSession.sessionWithConfiguration(configuration) &delegate(nil) delegateQueue(nil);

        var postDataTask: NSURLSessionDataTask := session.dataTaskWithRequest(request) completionHandler((data, response, taskError) ->
        begin

          var responseClass := NSHTTPURLResponse.class;
          var isKindOf := response.isKindOfClass(responseClass);

          if (not isKindOf) then
          begin
            NSLog('Non-HTTP response %@', taskError);
            exit;
          end;

          info := processResponse(data,NSHTTPURLResponse(response),taskError);
          dispatch_semaphore_signal(semaphore);

        end);

        postDataTask.resume;
        dispatch_semaphore_wait(semaphore, DISPATCH_TIME_FOREVER);

      end);

      var workerQueue := new NSOperationQueue();
      workerQueue.addOperations([outerExecutionBlock]) waitUntilFinished(true);

      exit info;

    end;

    method setup(issuer:String; _clientID:String;redirect:String;_stateKey:String);
    begin
      issuerURL := NSURL.URLWithString(issuer);
      clientID:= _clientID;
      redirectURL:= NSURL.URLWithString(redirect);
      StateKey := _stateKey;

      var archivedAuthState: NSData := NSUserDefaults.standardUserDefaults().objectForKey(StateKey);
      self._authState := OIDAuthState(NSKeyedUnarchiver.unarchiveObjectWithData(archivedAuthState));
      self._authState:stateChangeDelegate := self;

    end;

    property issuerURL:NSURL read private write;
    property redirectURL:NSURL read private write;
    property clientID:String read private write;
    property StateKey:String read private write;
    property &delegate:IAuthenticationInterestedParty;
    property AccessToken:String read get_AccessToken;

    method clear;
    begin
      AuthState := nil;
    end;

  end;

end.