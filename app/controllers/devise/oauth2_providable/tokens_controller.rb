class Devise::Oauth2Providable::TokensController < ApplicationController
  before_filter :authenticate_account!
  skip_before_filter :verify_authenticity_token, :only => :create

  def create
    @refresh_token = oauth2_current_refresh_token || oauth2_current_client.refresh_tokens.create!(:account_id => current_account.id)
    @access_token = @refresh_token.access_tokens.create!(:client => oauth2_current_client, :account_id => current_account.id)
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
