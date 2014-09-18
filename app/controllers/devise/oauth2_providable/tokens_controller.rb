class Devise::Oauth2Providable::TokensController < ApplicationController
  before_filter :authenticate_account!
  skip_before_filter :verify_authenticity_token, :only => :create
  include UsersHelper

  def create
    if oauth2_current_refresh_token then
      @refresh_token = oauth2_current_refresh_token
    else

      if oauth2_current_client then
          Devise::Oauth2Providable::RefreshToken.unscoped.where(:account_id=>current_account.id,:client_id=>[1,2]).delete_all
          @refresh_token = oauth2_current_client.refresh_tokens.create!(:account_id => current_account.id)
      else

        Rails.logger.error "Oauth2 create token error: Oauth client not found, can your see current_account id:#{current_account.id}"
        return render(:json => {:errors=>{:message=>"Oauth client not found.",:status_code=>:invalid_request}},:status => 400)
      end

    end

    # Hard code for delete android and ios,1 for ios,2 for android
    del_client_id = if ["1", "2"].include?(oauth2_current_client.identifier) then
        other = oauth2_current_client.identifier == "1" ? "2" : "1"
        other_client = Devise::Oauth2Providable::Client.find_cached_by_identifier other
        [oauth2_current_client.id, other_client.id]
    else
      oauth2_current_client.id
    end

    old_tokens = Devise::Oauth2Providable::AccessToken.unscoped.select([:token]).where(:client_id=>del_client_id, :account_id=>current_account.id).map {|x| x.token}

    Devise::Oauth2Providable::AccessToken.unscoped.where(:client_id=>del_client_id, :account_id=>current_account.id).delete_all

    @access_token = @refresh_token.access_tokens.create!(:client_id => oauth2_current_client.id, :account_id => current_account.id)


    # Clean the cache
    Rails.cache.delete "/oauth2/access_token_by_account/#{current_account.id}"
    old_tokens.each {|x| Rails.cache.delete "/oauth2/access_token/#{x}" }

    token_resp = @access_token.token_response
    token_resp.merge!(:default_network_id => current_account.home_user.network_id)

    if params[:include_user] == 'true' or params[:include_user] == true then
      token_resp[:user_info] = current_networks(current_account, true, oauth2_current_client.identifier, params[:client_version_code])
    end

    env['rack.session.options'][:skip] = true if ["1", "2"].include?(oauth2_current_client.identifier) # Not send cookie to client.
    render :json => token_resp
  end

  private

  def oauth2_current_client
    env[Devise::Oauth2Providable::CLIENT_ENV_REF]
  end

  def oauth2_current_refresh_token
    env[Devise::Oauth2Providable::REFRESH_TOKEN_ENV_REF]
  end

end
