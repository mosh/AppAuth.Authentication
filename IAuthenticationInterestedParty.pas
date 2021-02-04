namespace AppAuth.Authentication;

uses
  AppAuth.Authentication.Models;

type

  IAuthenticationInterestedParty = public interface
    method stateChanged(info:UserInfo);
  end;

end.