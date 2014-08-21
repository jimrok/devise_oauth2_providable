class Devise::Oauth2Providable::AccessToken < ActiveRecord::Base
  expires_according_to :access_token_expires_in

  before_validation :restrict_expires_at, :on => :create, :if => :refresh_token
  belongs_to :refresh_token

  attr_accessible :refresh_token, :account_id

  def token_response
    response = {
      :access_token => token,
      :token_type => 'bearer',
      :expires_in => expires_in 
    }
    response[:refresh_token] = refresh_token.token if refresh_token
    response
  end


  def self.find_current_access_token_by_account_id(account_id)
    Rails.cache.fetch "/oauth2/access_token_by_account/#{account_id}" do
      token = self.unscoped.find_by_account_id account_id
      token.token
    end
  end

  def self.find_cached_by_token(access_token)
    Rails.cache.fetch "/oauth2/access_token/#{access_token}" do
      find_by_token(access_token)
    end
  end

  def expire_cache
    Rails.cache.delete "/oauth2/access_token_by_account/#{self.account_id}"
    Rails.cache.delete "/oauth2/access_token/#{self.token}"
  end

  private

  def restrict_expires_at
    self.expires_at = [self.expires_at, refresh_token.expires_at].compact.min
  end
end
