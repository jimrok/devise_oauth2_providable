class Devise::Oauth2Providable::AuthorizationCode < ActiveRecord::Base
  expires_according_to :authorization_code_expires_in

  def account
  	Account.find_cached_by_id self.account_id
  end
end
