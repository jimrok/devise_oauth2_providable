class Devise::Oauth2Providable::TokensController < ApplicationController
  before_filter :authenticate_account!
  skip_before_filter :verify_authenticity_token, :only => :create

  def create
    if oauth2_current_refresh_token then
      @refresh_token = oauth2_current_refresh_token
    else
      Devise::Oauth2Providable::RefreshToken.where(:account_id=>current_account.id,:client_id=>[1,2]).delete_all
      @refresh_token = oauth2_current_client.refresh_tokens.create!(:account_id => current_account.id)
    end

    # Hard code for delete android and ios,1 for ios,2 for android
    del_client_id = if [1,2].include?(oauth2_current_client.id) then
      [1,2]
    else
      oauth2_current_client.id
    end

    old_tokens = Devise::Oauth2Providable::AccessToken.select([:token]).where(:client_id=>del_client_id, :account_id=>current_account.id).map {|x| x.token}

    Devise::Oauth2Providable::AccessToken.where(:client_id=>del_client_id, :account_id=>current_account.id).delete_all

    @access_token = @refresh_token.access_tokens.create!(:client => oauth2_current_client, :account_id => current_account.id)


    # Clean the cache
    Rails.cache.delete "/oauth2/access_token_by_account/#{current_account.id}"
    old_tokens.each {|x| Rails.cache.delete "/oauth2/access_token/#{x}" }

    render :json => @access_token.token_response
  end

  private

  def oauth2_current_client
    env[Devise::Oauth2Providable::CLIENT_ENV_REF]
  end
  def oauth2_current_refresh_token
    env[Devise::Oauth2Providable::REFRESH_TOKEN_ENV_REF]
  end

end
