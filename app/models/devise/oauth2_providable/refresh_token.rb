class Devise::Oauth2Providable::RefreshToken < ActiveRecord::Base
  expires_according_to :refresh_token_expires_in

  #attr_accessible :access_tokens, :account_id

  has_many :access_tokens

  def account
  	Account.find_cached_by_id self.account_id
  end
  
end
