namespace AppAuth.Authentication;

type

  IAuthenticationInterestedParty = public interface
    method stateChanged(info:UserInfo);
  end;

end.