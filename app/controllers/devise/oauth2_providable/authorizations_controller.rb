#encoding: utf-8

module Devise
  module Oauth2Providable
    class AuthorizationsController < ApplicationController
      skip_before_filter :authenticate_account!
      layout "oauth"

      rescue_from Rack::OAuth2::Server::Authorize::BadRequest do |e|
        @error = e
        render :error, :status => e.status
      end

      def new
        params[:client_id]=params[:app_id]
        request.params[:client_id]=request.params[:app_id]
        respond *authorize_endpoint.call(request.env)
      end


      def login_approval

        if params[:deny].present? then
          respond *authorize_endpoint(:allow_approval).call(request.env)
        else

          warden = request.env['warden']
          # warden.authenticate(:password_authenticatable)
          # account = warden.user(:account)
          #account = warden.authenticate!

          resource =  Account.find_for_authentication(params)
          password = params[:password]

          account = if Account.valid_account?(resource,password)
            resource.after_database_authentication
            
            if resource.home_user.role_code == ::Const::OFFICIAL_ACCOUNT_ROLE_CODE then
              nil
            else
              resource
            end
            
          else
            nil
          end


          
          if (account) then

            @resource = account
            sign_in(:account,@resource)
            respond *authorize_endpoint(:allow_approval).call(request.env)

          else
            login_name = params[:login_name]

            @resource = Account.new(:login_name=>login_name)
            @resource.errors.add(:email, "帐号或密码不正确")
            authorize_endpoint.call(request.env)
            render "session"
          end
        end
      end

      def create
        respond *authorize_endpoint(:allow_approval).call(request.env)
      end

      def me
        access_token=params[:access_token]
        network_name=params[:network_name]
        token_object=Devise::Oauth2Providable::AccessToken.find_by_token(access_token)
        result=Hash.new
        if token_object then
          network_url = URI.decode(network_name)
          network = Network.find_network_by_url(network_url)
          if network then
            result[:code]=0
            result[:client_id]=token_object.client_id
            result[:network_id]=network.id
            result[:access_token]=token_object.token
            result[:expires_in]=token_object.expires_in
          else
            result[:code]=2
            result[:error_desc]="The network not exist."
          end
        else
          result[:code]=1
          result[:error_desc]="The token has expired."
        end
        render_jsonp result
      end
      private

      def respond(status, header, response)
        ["WWW-Authenticate"].each do |key|
          headers[key] = header[key] if header[key].present?
        end
        if response.redirect?
          redirect_to header['Location']
        elsif !account_signed_in?
          render "session"
        else
          render :new
        end
      end

      def authorize_endpoint(allow_approval = false)
        Rack::OAuth2::Server::Authorize.new do |req, res|

          @client = Client.find_cached_by_identifier(req.client_id) || req.bad_request!

          if req.response_type==:token && Regexp.new(req.env["HTTP_HOST"]+"/connect/redirect-1.0.0.html")=~ req.params["redirect_uri"] then
            #如果是jsAPI请求，不需要校验跟注册客户端的回调地址
            res.redirect_uri =@redirect_uri=req.params["redirect_uri"];
          else
            res.redirect_uri = @redirect_uri = req.verify_redirect_uri!(@client.redirect_uri,true)
          end
          if allow_approval
            if params[:approve].present?
              case req.response_type
              when :code
                authorization_code = current_account.authorization_codes.create!(:client_id => @client.identifier,:account_id => current_account.id)
                res.code = authorization_code.token
              when :token
                #binding.pry
                warden = request.env['warden']
                account = warden.user(:account)
                access_token = current_account.access_tokens.create!(:client_id => @client.identifier,:account_id => current_account.id)
                # token_str=access_token.token
                # bearer_token = Rack::OAuth2::AccessToken::Bearer.new(:access_token => token_str)
                res.access_token = access_token
              end
              res.approve!
            else
              req.access_denied!
            end
          else
            @response_type = req.response_type
          end
        end
      end
    end
  end
end
