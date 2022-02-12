namespace AppAuth.Authentication.Helpers;

uses
  AppAuth,
  AppAuth.Authentication.Models,
  Foundation, RemObjects.Elements.RTL;

type
  UserInfoHelper = public class
  private

    class method fillUserInfo(obj:NSDictionary):UserInfo;
    begin
      var info := new UserInfo;
      info.FamilyName := obj['family_name'];
      info.Gender := obj['gender'];
      info.GivenName := obj['given_name'];
      info.Locale := obj['locale'];
      info.Name := obj['name'];
      info.Picture := obj['picture'];
      info.Email := obj['email'];
      exit info;
    end;

    class method processResponse(data:NSData; httpResponse: NSHTTPURLResponse; taskError:NSError):UserInfo;
    begin
      var info:UserInfo:=nil;
      var jsonError: NSError;

      var jsonDictionaryOrArray := NSJSONSerialization.JSONObjectWithData(data) options(0) error(var jsonError);

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

      if(jsonDictionaryOrArray is NSDictionary)then
      begin
        info := fillUserInfo(NSDictionary(jsonDictionaryOrArray));
      end
      else
      begin
        raise new NotImplementedException;
      end;


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