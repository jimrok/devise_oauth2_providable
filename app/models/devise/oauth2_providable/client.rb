class Devise::Oauth2Providable::Client < ActiveRecord::Base
  has_many :access_tokens
  has_many :refresh_tokens
  has_many :authorization_codes
  has_many :versions, :class_name => "Oauth2ClientVersion"

  before_validation :customer_identifier, :on => :create, :unless => :identifier?
  before_validation :init_secret, :on => :create, :unless => :secret?
  validates :website, :secret, :presence => true
  validates :name, :presence => true, :uniqueness => true
  validates :identifier, :presence => true, :uniqueness => true

  attr_accessible :name, :identifier, :website, :redirect_uri, :latest_version_id, :description,:upgrade_url,:at_hoc
  belongs_to :latest_version, :class_name => "Oauth2ClientVersion", :foreign_key => "latest_version_id"

  def file_name
      name
  end
  def file_dir
    File.realpath("#{Rails.root}/contents")+"/applications/#{id}/"
  end
  private

  def customer_identifier
      max_client = Devise::Oauth2Providable::Client.order("identifier+0 desc").first
      client_id = max_client.identifier.to_i if max_client
      if client_id > 1000 then
          self.identifier = "#{client_id + 1}"
      else
          self.identifier = "1001"
      end
  end

  def init_identifier
    self.identifier = Devise::Oauth2Providable.random_id
  end

  def init_secret
    self.secret = Devise::Oauth2Providable.random_id
  end
end
