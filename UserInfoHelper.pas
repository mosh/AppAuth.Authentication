namespace AppAuth.Authentication;

uses
  AppAuth,
  Foundation;

type
  UserInfoHelper = public class
  private

    class method fillUserInfo(jsonDictionaryOrArray:id):UserInfo;
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


    class method processResponse(data:NSData; httpResponse: NSHTTPURLResponse; taskError:NSError):UserInfo;
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
          NSLog('Authorization Error (%@). Response: %@', oauthError, responseText);
          taskError:=oauthError;
        end
        else
        begin
          NSLog('HTTP: %d. Response: %@', Integer(httpResponse.statusCode), responseText);
        end;

        exit;
      end;

      info := fillUserInfo(jsonDictionaryOrArray);

      exit info;
    end;

  public

    class method getUserInfo(accessToken:String; userinfoEndpoint: NSURL;error:NSError):UserInfo;
    begin
      var info:UserInfo := nil;

      var outerExecutionBlock: NSBlockOperation := NSBlockOperation.blockOperationWithBlock(method begin

        var semaphore := dispatch_semaphore_create(0);

        var request: NSMutableURLRequest := NSMutableURLRequest.requestWithURL(userinfoEndpoint);
        var authorizationHeaderValue: NSString := NSString.stringWithFormat('Bearer %@', accessToken);
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
            error:=taskError;
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
  end;

end.