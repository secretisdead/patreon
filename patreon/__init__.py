import uuid
import time
import re
from ipaddress import ip_address
from datetime import datetime, timezone
import urllib
import json

from sqlalchemy import Table, Column, PrimaryKeyConstraint, Binary as sqla_binary
from sqlalchemy import Integer, String, MetaData
from sqlalchemy.dialects.mysql import VARBINARY as mysql_binary
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import func, and_, or_
import dateutil.parser

from statement_helper import sort_statement, paginate_statement, id_filter
from statement_helper import time_cutoff_filter, string_equal_filter
from statement_helper import string_like_filter, bitwise_filter
from statement_helper import int_equal_filter, int_cutoff_filter
from base64_url import base64_url_encode, base64_url_decode
from idcollection import IDCollection
from parse_id import parse_id

def get_id_bytes(id):
	if isinstance(id, bytes):
		return id
	return base64_url_decode(id)

def generate_or_parse_id(id):
	if not id:
		id_bytes = uuid.uuid4().bytes
		id = base64_url_encode(id_bytes)
	else:
		id, id_bytes = parse_id(id)
	return (id, id_bytes)

class PatreonClient:
	def __init__(
			self,
			id=None,
			creation_time=None,
			client_id='',
			client_secret='',
			webhook_secret='',
			access_token='',
			access_token_expiration_time=0,
			refresh_token='',
			campaign_id=0,
			creation_name='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		current_time = time.time()

		if None == creation_time:
			creation_time = current_time
		self.creation_time = int(creation_time)
		self.creation_datetime = datetime.fromtimestamp(
			self.creation_time,
			timezone.utc,
		)

		self.client_id = client_id
		self.client_secret = client_secret
		self.webhook_secret = webhook_secret
		self.access_token = access_token

		self.access_token = access_token

		self.access_token_expiration_time = int(access_token_expiration_time)
		self.access_token_expiration_datetime = datetime.fromtimestamp(
			self.access_token_expiration_time,
			timezone.utc,
		)

		self.refresh_token = refresh_token
		self.campaign_id = campaign_id
		self.creation_name = creation_name

class PatreonMember:
	def __init__(
			self,
			id=None,
			client_id='',
			campaign_id=0,
			tier_id=0,
			user_id=0,
			amount_cents=0,
			last_fulfill_time=0,
			last_charge_time=0,
			last_charge_status='',
			lifetime_support_cents=0,
			pledge_relationship_start_time=0,
			name='',
		):
		self.id, self.id_bytes = generate_or_parse_id(id)

		self.client_id, self.client_id_bytes = parse_id(client_id)
		self.campaign_id = int(campaign_id)
		self.tier_id = int(tier_id)
		self.user_id = int(user_id)
		self.amount_cents = int(amount_cents)

		self.last_fulfill_time = int(last_fulfill_time)
		self.last_fulfill_datetime = datetime.fromtimestamp(
			self.last_fulfill_time,
			timezone.utc,
		)

		self.last_charge_time = int(last_charge_time)
		self.last_charge_datetime = datetime.fromtimestamp(
			self.last_charge_time,
			timezone.utc,
		)

		self.last_charge_status = str(last_charge_status)
		self.lifetime_support_cents = int(lifetime_support_cents)

		self.pledge_relationship_start_time = int(pledge_relationship_start_time)
		self.pledge_relationship_start_datetime = datetime.fromtimestamp(
			self.pledge_relationship_start_time,
			timezone.utc,
		)

		self.name = str(name)

class Patreon:
	def __init__(self, engine, db_prefix='', install=False):
		self.engine = engine
		self.engine_session = sessionmaker(bind=self.engine)()

		self.db_prefix = db_prefix

		self.client_id_length = 64
		self.client_secret_length = 64
		self.webhook_secret_length = 64
		self.access_token_length = 64
		self.refresh_token_length = 64
		self.creation_name_length = 128
		self.tier_title_length = 64
		self.benefit_title_length = 64
		self.benefit_rule_type_length = 32
		self.member_last_charge_status_length = 32
		self.member_name_length = 64
		self.scope_length = 16

		metadata = MetaData()

		default_bytes = 0b0 * 16

		if 'mysql' == self.engine_session.bind.dialect.name:
			Binary = mysql_binary
		else:
			Binary = sqla_binary

		# clients tables
		self.clients = Table(
			self.db_prefix + 'patreon_clients',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('creation_time', Integer, default=0),
			Column('client_id', String(self.client_id_length), default=''),
			Column(
				'client_secret',
				String(self.client_secret_length),
				default='',
			),
			Column(
				'webhook_secret',
				String(self.webhook_secret_length),
				default='',
			),
			Column(
				'access_token',
				String(self.access_token_length),
				default='',
			),
			Column('access_token_expiration_time', Integer, default=0),
			Column(
				'refresh_token',
				String(self.refresh_token_length),
				default='',
			),
			#TODO is this always a number?
			Column('campaign_id', Integer, default=0),
			Column(
				'creation_name',
				String(self.creation_name_length),
				default='',
			),
			PrimaryKeyConstraint('id'),
		)
		# tiers tables
		self.tiers = Table(
			self.db_prefix + 'patreon_tiers',
			metadata,
			#TODO is this always a number?
			Column('id', Integer, default=0),
			Column('client_id', Binary(16), default=default_bytes),
			Column('campaign_id', Integer, default=0),
			Column('title', String(self.tier_title_length), default=''),
			Column('amount_cents', Integer, default=0),
			Column('unpublished', Integer, default=0),
			PrimaryKeyConstraint('id', 'client_id'),
		)
		self.tier_permissions = Table(
			self.db_prefix + 'patreon_tier_permissions',
			metadata,
			Column('client_id', Binary(16), default=default_bytes),
			Column('campaign_id', Integer, default=0),
			Column('tier_id', Integer, default=0),
			Column('length', Integer, default=0),
			Column('shareable', Integer, default=0),
			Column('scope', String(self.scope_length), default=''),
			Column('group_bits', Integer, default=0),
		)

		# benefits tables
		self.benefits = Table(
			self.db_prefix + 'patreon_benefits',
			metadata,
			#TODO is this always a number?
			Column('id', Integer, default=0),
			Column('client_id', Binary(16), default=default_bytes),
			Column('campaign_id', Integer, default=0),
			Column('title', String(self.benefit_title_length), default=''),
			Column(
				'rule_type',
				String(self.benefit_rule_type_length),
				default='',
			),
			Column('next_deliverable_due_time', Integer, default=0),
			PrimaryKeyConstraint('id', 'client_id'),
		)
		self.benefit_permissions = Table(
			self.db_prefix + 'patreon_benefit_permissions',
			metadata,
			Column('client_id', Binary(16), default=default_bytes),
			Column('campaign_id', Integer, default=0),
			Column('benefit_id', Integer, default=0),
			Column('length', Integer, default=0),
			Column('shareable', Integer, default=0),
			Column('scope', String(self.scope_length), default=''),
			Column('group_bits', Integer, default=0),
		)

		# members tables
		self.members = Table(
			self.db_prefix + 'patreon_members',
			metadata,
			Column('id', Binary(16), default=default_bytes),
			Column('client_id', Binary(16), default=default_bytes),
			Column('campaign_id', Integer, default=0),
			Column('tier_id', Integer, default=0),
			#TODO is this always a number?
			Column('user_id', Integer, default=0),
			Column('amount_cents', Integer, default=0),
			Column('last_fulfill_time', Integer, default=0),
			Column('last_charge_time', Integer, default=0),
			Column(
				'last_charge_status',
				String(self.member_last_charge_status_length),
				default='',
			),
			Column('lifetime_support_cents', Integer, default=0),
			Column('pledge_relationship_start_time', Integer, default=0),
			#TODO in a larger use case with more separate campaigns
			#TODO which might have user overlap, patron user_ids/names could
			#TODO be stored in another table and crossreferenced
			#TODO but for now store them directly on the member record
			#TODO and eat any minor redundancy
			Column('name', String(self.member_name_length), default=''),
			PrimaryKeyConstraint('id', 'client_id'),
		)

		self.connection = self.engine.connect()

		if install:
			for table in [
					self.clients,
					self.tiers,
					self.tier_permissions,
					self.benefits,
					self.benefit_permissions,
					self.members,
				]:
				table.create(bind=self.engine, checkfirst=True)

	def uninstall(self):
		for table in [
				self.clients,
				self.tiers,
				self.tier_permissions,
				self.benefits,
				self.benefit_permissions,
				self.members,
			]:
			table.drop(self.engine)

	# retrieve clients
	def get_client(self, id):
		clients = self.search_clients(filter={'ids': id})
		return clients.get(id)

	def prepare_clients_search_statement(self, filter):
		conditions = []
		conditions += id_filter(filter, 'ids', self.clients.c.id)
		conditions += time_cutoff_filter(
			filter,
			'created',
			self.clients.c.creation_time,
		)
		conditions += string_equal_filter(
			filter,
			'client_ids',
			self.clients.c.client_id,
		)
		conditions += string_like_filter(
			filter,
			'creation_names',
			self.clients.c.creation_name,
		)
		conditions += time_cutoff_filter(
			filter,
			'access_token_expired',
			self.clients.c.access_token_expiration_time,
		)

		statement = self.clients.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_clients(self, filter={}):
		statement = self.prepare_clients_search_statement(filter)
		statement = statement.with_only_columns([func.count(self.clients.c.id)])
		return self.connection.execute(statement).fetchone()[0]

	def search_clients(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None,
		):
		statement = self.prepare_clients_search_statement(filter)

		statement = sort_statement(
			statement,
			self.clients,
			sort,
			order,
			'creation_time',
			True,
			[
				'creation_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		clients = IDCollection()
		for row in result:
			client = PatreonClient(
				id=row[self.clients.c.id],
				creation_time=row[self.clients.c.creation_time],
				client_id=row[self.clients.c.client_id],
				client_secret=row[self.clients.c.client_secret],
				webhook_secret=row[self.clients.c.webhook_secret],
				access_token=row[self.clients.c.access_token],
				access_token_expiration_time=row[self.clients.c.access_token_expiration_time],
				refresh_token=row[self.clients.c.refresh_token],
				campaign_id=row[self.clients.c.campaign_id],
				creation_name=row[self.clients.c.creation_name],
			)

			clients.add(client)
		return clients

	# manipulate clients
	def create_client(self, **kwargs):
		client = PatreonClient(**kwargs)
		# preflight check for existing id
		if self.get_client(client.id_bytes):
			raise ValueError('Client ID collision')
		self.connection.execute(
			self.clients.insert(),
			id=client.id_bytes,
			creation_time=int(client.creation_time),
			client_id=str(client.client_id),
			client_secret=str(client.client_secret),
			webhook_secret=str(client.webhook_secret),
			access_token=str(client.access_token),
			access_token_expiration_time=int(client.access_token_expiration_time),
			refresh_token=str(client.refresh_token),
			campaign_id=str(client.campaign_id),
			creation_name=str(client.creation_name),
		)
		return client

	def update_client(self, id, **kwargs):
		client = PatreonClient(id=id, **kwargs)
		updates = {}
		if 'creation_time' in kwargs:
			updates['creation_time'] = int(client.creation_time)
		if 'client_id' in kwargs:
			updates['client_id'] = str(client.client_id)
		if 'client_secret' in kwargs:
			updates['client_secret'] = str(client.client_secret)
		if 'webhook_secret' in kwargs:
			updates['webhook_secret'] = str(client.webhook_secret)
		if 'access_token' in kwargs:
			updates['access_token'] = str(client.access_token)
		if 'access_token_expiration_time' in kwargs:
			updates['access_token_expiration_time'] = int(client.access_token_expiration_time)
		if 'refresh_token' in kwargs:
			updates['refresh_token'] = str(client.refresh_token)
		if 'campaign_id' in kwargs:
			updates['campaign_id'] = str(client.campaign_id)
		if 'creation_name' in kwargs:
			updates['creation_name'] = str(client.creation_name)
		if 0 == len(updates):
			return client
		self.connection.execute(
			self.clients.update().values(**updates).where(
				self.clients.c.id == client.id_bytes
			)
		)
		return client

	def delete_client(self, id):
		id = get_id_bytes(id)
		self.connection.execute(
			self.clients.delete().where(self.clients.c.id == id)
		)

	def refresh_client_tokens(self, client, redirect_uri):
		uri = (
			'https://www.patreon.com/api/oauth2/token'
				+ '?grant_type=refresh_token'
				+ '&refresh_token=' + client.refresh_token
				+ '&client_id=' + client.client_id
				+ '&client_secret=' + client.client_secret
				+ '&redirect_uri=' + redirect_uri
		)
		req = urllib.request.Request(uri, data=b'')
		req.add_header('User-Agent', 'Mozilla')

		response = urllib.request.urlopen(req)

		if not response:
			raise ValueError('Empty access token response')

		response = json.loads(response.read())

		client.access_token = response['access_token']
		expires_at = int(response['expires_in']) + time.time()
		client.access_token_expiration_datetime = datetime.fromtimestamp(
			expires_at,
			timezone.utc,
		)
		client.access_token_expiration_time = int(
			client.access_token_expiration_datetime.timestamp()
		)
		client.refresh_token = response['refresh_token']
		self.connection.execute(
			self.clients.update().values({
				'access_token': str(client.access_token),
				'refresh_token': str(client.refresh_token),
				'access_token_expiration_time': int(
					client.access_token_expiration_time
				),
			}).where(
				self.clients.c.id == client.id_bytes
			)
		)
		return
		self.update_client(
			client.id_bytes,
			access_token=client.access_token,
			access_token_expiration_time=client.access_token_expiration_time,
			refresh_token=client.refresh_token,
		)

	def client_request_failure(self, uri, client, redirect_uri, last_try=False):
		if last_try:
			#TODO pass specific exception information back up
			raise
		# handle expired token exceptions by trying to refresh token
		self.refresh_client_tokens(client, redirect_uri)
		# re-attempt client request with new credentials one more time
		self.client_request(uri, client, redirect_uri, True)

	def client_request(self, uri, client, redirect_uri, last_try=False):
		req = urllib.request.Request(uri)
		req.add_header('Authorization', 'Bearer ' + client.access_token)
		try:
			response = urllib.request.urlopen(req)
		except Exception as e:
			raise
		except urllib.error.HTTPError as e:
			client_request_failure(uri, client, redirect_uri, last_try)
		except urllib.error.URLError as e:
			client_request_failure(uri, client, redirect_uri, last_try)
		else:
			if not response:
				raise ValueError('Empty client request response')

			response = json.loads(response.read())
			return response

	def refresh_client(self, client, redirect_uri):
		response = self.client_request(
			(
				'https://www.patreon.com/api/oauth2/v2/campaigns'
					+ '?' + urllib.parse.quote_plus('fields[campaign]') + '='
					+ 'creation_name'
			),
			client,
			redirect_uri
		)
		# parse included data
		campaigns = {}
		for row in response['data']:
			if 'campaign' == row['type']:
				campaigns[int(row['id'])] = row['attributes']['creation_name']
		# there should only be one campaign per client, right?
		campaign_id, creation_name = next(iter(campaigns.items()))
		# set campaign id/creation name for this client
		self.connection.execute(
			self.clients.update().values(
				campaign_id=int(campaign_id),
				creation_name=str(creation_name),
			).where(
				self.clients.c.id == client.id_bytes
			)
		)

		benefits = {}
		tiers = {}
		for campaign_id in campaigns.keys():
			# first page
			response = {
				'links': {
					'next': (
						'https://www.patreon.com/api/oauth2/v2/campaigns/'
							+ str(campaign_id)
							+ '?include='
							+ 'tiers'
							+ ',benefits'
							+ '&' + urllib.parse.quote_plus('fields[benefit]') + '='
							+ 'title'
							+ ',rule_type'
							+ ',next_deliverable_due_date'
							+ '&' + urllib.parse.quote_plus('fields[tier]') + '='
							+ 'title'
							+ ',amount_cents'
							+ ',unpublished_at'
					)
				}
			}
			while (
					'links' in response
					and 'next' in response['links']
					and response['links']['next']
				):
				response = self.client_request(
					response['links']['next'],
					client,
					redirect_uri
				)
				if (
						'data' in response
						and 'campaign' == response['data']['type']
						and 'included' in response
					):
					# non-tier pledge
					tiers[uuid.uuid4()] = {
						'id': 0,
						'client_id': client.id_bytes,
						'campaign_id': campaign_id,
						'amount_cents': 1,
						'title': 'Non-tier Pledge',
						'amount_cents': 1,
						'unpublished': 0,
					}
					for resource in response['included']:
						if (
								'attributes' not in resource
								or 'id' not in resource
								or 'type' not in resource
							):
							continue
						resource_id = int(resource['id'])
						if 'benefit' == resource['type']:
							# parse string datetime into timestamp
							try:
								parsed = dateutil.parser.parse(
									resource['attributes']['next_deliverable_due_date']
								)
							except ValueError:
								next_deliverable_due_time = 0
							except TypeError:
								next_deliverable_due_time = 0
							else:
								next_deliverable_due_time = int(parsed.timestamp())
							benefits[resource_id] = {
								'id': resource_id,
								'client_id': client.id_bytes,
								'campaign_id': campaign_id,
								'title': str(resource['attributes']['title']),
								'rule_type': str(resource['attributes']['rule_type']),
								'next_deliverable_due_time': next_deliverable_due_time,
							}
						elif 'tier' == resource['type']:
							tiers[resource_id] = {
								'id': resource_id,
								'client_id': client.id_bytes,
								'campaign_id': campaign_id,
								'title': str(resource['attributes']['title']),
								'amount_cents': int(resource['attributes']['amount_cents']),
								'unpublished': 0,
							}
							if (
									'unpublished_at' in resource['attributes']
									and resource['attributes']['unpublished_at']
								):
								tiers[resource_id]['unpublished'] = 1
			members = {}
			# first page
			response = {
				'links': {
					'next': (
						'https://www.patreon.com/api/oauth2/v2/campaigns/'
							+ str(campaign_id)
							+ '/members'
							+ '?include='
							+ 'currently_entitled_tiers'
							+ ',user'
							+ '&' + urllib.parse.quote_plus('fields[user]') + '='
							+ 'full_name'
							+ '&' + urllib.parse.quote_plus('fields[member]') + '='
							+ 'patron_status'
							+ ',pledge_relationship_start'
							+ ',lifetime_support_cents'
							+ ',currently_entitled_amount_cents'
							+ ',last_charge_date'
							+ ',last_charge_status'
					)
				}
			}
			while (
					'links' in response
					and 'next' in response['links']
					and response['links']['next']
				):
				response = self.client_request(
					response['links']['next'],
					client,
					redirect_uri
				)
				if (
						'data' not in response
						or 'included' not in response
					):
					continue
				user_ids_to_names = {}
				for resource in response['included']:
					if (
							'id' not in resource
							or 'type' not in resource
							or 'user' != resource['type']
							or 'attributes' not in resource
							or 'full_name' not in resource['attributes']
						):
						continue
					resource_id = int(resource['id'])
					user_ids_to_names[resource_id] = resource['attributes']['full_name']
				for member in response['data']:
					if (
							'id' not in member
							or 'type' not in member
							or 'member' != member['type']
							or 'relationships' not in member
							or 'user' not in member['relationships']
							or 'data' not in member['relationships']['user']
							or 'user' != member['relationships']['user']['data']['type']
							or 'attributes' not in member
							or 'currently_entitled_amount_cents' not in member['attributes']
							or 'last_charge_date' not in member['attributes']
							or 'last_charge_status' not in member['attributes']
							or 'lifetime_support_cents' not in member['attributes']
							or 'patron_status' not in member['attributes']
							or 'active_patron' != member['attributes']['patron_status']
							or 'pledge_relationship_start' not in member['attributes']
						):
						continue
					# parse member uuid
					member_uuid = uuid.UUID(member['id'])
					member_id, member_id_bytes = parse_id(member_uuid.bytes)
					if (
							'currently_entitled_tiers' not in member['relationships']
							or 'data' not in member['relationships']['currently_entitled_tiers']
							or not member['relationships']['currently_entitled_tiers']['data']
							or 'tier' != member['relationships']['currently_entitled_tiers']['data'][0]['type']
							or 'id' not in member['relationships']['currently_entitled_tiers']['data'][0]
						):
						tier_id = 0
					else:
						tier_id = int(
							member['relationships']['currently_entitled_tiers']['data'][0]['id']
						)
					user_id = int(member['relationships']['user']['data']['id'])
					if tier_id < 1:
						tier_id = 0
					# parse string datetime into timestamp
					try:
						parsed = dateutil.parser.parse(
							member['attributes']['pledge_relationship_start']
						)
					except ValueError:
						pledge_relationship_start_time = 0
					except TypeError:
						pledge_relationship_start_time = 0
					else:
						pledge_relationship_start_time = int(parsed.timestamp())
					try:
						parsed = dateutil.parser.parse(
							member['attributes']['last_charge_date']
						)
					except ValueError:
						last_charge_time = 0
					except TypeError:
						last_charge_time = 0
					else:
						last_charge_time = int(parsed.timestamp())
					members[member_id] = {
						'id': member_id_bytes,
						'client_id': client.id_bytes,
						'campaign_id': campaign_id,
						'tier_id': tier_id,
						'user_id': user_id,
						'amount_cents': int(
							member['attributes']['currently_entitled_amount_cents']
						),
						'last_charge_time': last_charge_time,
						'last_charge_status': str(member['attributes']['last_charge_status']),
						'lifetime_support_cents': int(
							member['attributes']['lifetime_support_cents']
						),
						'pledge_relationship_start_time': pledge_relationship_start_time,
						'name': '',
					}
					if user_id in user_ids_to_names:
						members[member_id]['name'] = user_ids_to_names[user_id]
		# get existing member last_fulfill_time values to add before insertion
		fulfilled_members = self.search_members(filter={'last_fulfilled_after': 0})
		# delete stale info and insert new infor for this client
		for table in ['benefits', 'tiers', 'members']:
			self.connection.execute(getattr(self, table).delete().where(
				getattr(self, table).c.client_id == client.id_bytes)
			)
		if benefits:
			self.connection.execute(
				self.benefits.insert().values(list(benefits.values()))
			)
		if tiers:
			self.connection.execute(
				self.tiers.insert().values(list(tiers.values()))
			)
		if members:
			# not using indexed dict for insert
			members = list(members.values())
			# add last_fulfill_time to members that were previously fulfilled
			for member in members:
				if member['id'] in fulfilled_members:
					fulfilled_member = fulfilled_members.get(member['id'])
					member['last_fulfill_time'] = fulfilled_member.last_fulfill_time
			# sqlite needs smaller chunks for mass insertion
			i = 0
			per_insert = 50
			while members:
				current_chunk = members[:50]
				self.connection.execute(
					self.members.insert().values(current_chunk)
				)
				del members[:50]

	def populate_client_tiers(self, client):
		client.tiers = {}
		result = self.connection.execute(
			self.tiers.select().where(
				self.tiers.c.client_id == client.id_bytes
			).order_by(self.tiers.c.amount_cents.asc())
		).fetchall()
		for row in result:
			tier = {
				'id': row[self.tiers.c.id],
				'campaign_id': row[self.tiers.c.campaign_id],
				'title': row[self.tiers.c.title],
				'amount_cents': row[self.tiers.c.amount_cents],
				'unpublished': False,
			}
			if row[self.tiers.c.unpublished]:
				tier['unpublished'] = True
			client.tiers[row[self.tiers.c.id]] = tier

	def populate_client_benefits(self, client):
		client.benefits = {}
		result = self.connection.execute(
			self.benefits.select().where(
				self.benefits.c.client_id == client.id_bytes
			).order_by(self.benefits.c.next_deliverable_due_time.asc())
		).fetchall()
		for row in result:
			benefit = {
				'id': row[self.benefits.c.id],
				'campaign_id': row[self.benefits.c.campaign_id],
				'title': row[self.benefits.c.title],
				'rule_type': row[self.benefits.c.rule_type],
				'next_deliverable_due_time': row[self.benefits.c.next_deliverable_due_time],
			}
			benefit['next_deliverable_due_datetime'] = datetime.fromtimestamp(
				benefit['next_deliverable_due_time'],
				timezone.utc,
			)
			client.benefits[row[self.benefits.c.id]] = benefit

	# retrieve members
	def get_member(self, id):
		members = self.search_members(filter={'ids': id})
		return members.get(id)

	def prepare_members_search_statement(self, filter):
		conditions = []
		conditions += id_filter(filter, 'ids', self.members.c.id)
		conditions += id_filter(filter, 'client_ids', self.members.c.client_id)
		conditions += int_equal_filter(
			filter,
			'campaign_ids',
			self.members.c.campaign_id,
		)
		conditions += int_equal_filter(
			filter,
			'tier_ids',
			self.members.c.tier_id,
		)
		conditions += int_equal_filter(
			filter,
			'user_ids',
			self.members.c.user_id,
		)
		conditions += int_cutoff_filter(
			filter,
			'amount_cents_less_than',
			'amount_cents_more_than',
			self.members.c.amount_cents,
		)
		conditions += time_cutoff_filter(
			filter,
			'last_fulfilled',
			self.members.c.last_fulfill_time,
		)
		conditions += time_cutoff_filter(
			filter,
			'last_charged',
			self.members.c.last_charge_time,
		)
		conditions += string_equal_filter(
			filter,
			'last_charge_status',
			self.members.c.last_charge_status,
		)
		conditions += int_cutoff_filter(
			filter,
			'lifetime_support_cents_less_than',
			'lifetime_support_cents_more_than',
			self.members.c.lifetime_support_cents,
		)
		conditions += time_cutoff_filter(
			filter,
			'pledged',
			self.members.c.pledge_relationship_start_time,
		)
		conditions += string_like_filter(
			filter,
			'names',
			self.members.c.name,
		)
		if 'charged_after_fulfilled' in filter:
			conditions += [
				self.members.c.last_charge_time > self.members.c.last_fulfill_time
			]

		statement = self.members.select()
		if conditions:
			statement = statement.where(and_(*conditions))
		return statement

	def count_members(self, filter={}):
		statement = self.prepare_members_search_statement(filter)
		statement = statement.with_only_columns([func.count(self.members.c.id)])
		return self.connection.execute(statement).fetchone()[0]

	def search_members(
			self,
			filter={},
			sort='',
			order='',
			page=0,
			perpage=None,
		):
		statement = self.prepare_members_search_statement(filter)

		statement = sort_statement(
			statement,
			self.members,
			sort,
			order,
			'pledge_relationship_start_time',
			True,
			[
				'pledge_relationship_start_time',
				'id',
			],
		)
		statement = paginate_statement(statement, page, perpage)

		result = self.connection.execute(statement).fetchall()
		if 0 == len(result):
			return IDCollection()

		members = IDCollection()
		for row in result:
			member = PatreonMember(
				id=row[self.members.c.id],
				client_id=row[self.members.c.client_id],
				campaign_id=row[self.members.c.campaign_id],
				tier_id=row[self.members.c.tier_id],
				user_id=row[self.members.c.user_id],
				amount_cents=row[self.members.c.amount_cents],
				last_fulfill_time=row[self.members.c.last_fulfill_time],
				last_charge_time=row[self.members.c.last_charge_time],
				last_charge_status=row[self.members.c.last_charge_status],
				lifetime_support_cents=row[self.members.c.lifetime_support_cents],
				pledge_relationship_start_time=row[self.members.c.pledge_relationship_start_time],
				name=row[self.members.c.name],
			)

			members.add(member)
		return members

	def set_members_last_fulfill_time(self, member_ids, last_fulfill_time=None):
		if not last_fulfill_time:
			last_fulfill_time = time.time()
		if list != type(member_ids):
			member_ids = [member_ids]
		conditions = []
		for member_id in member_ids:
			try:
				member_id, member_id_bytes = parse_id(member_id)
			except:
				# raise instead of consuming bad ids?
				continue
			conditions.append(self.members.c.id == member_id_bytes)
		if not conditions:
			# raise instead of early return for no valid ids?
			return
		self.connection.execute(
			self.members.update().values(
				last_fulfill_time=int(last_fulfill_time)
			).where(or_(*conditions))
		)

	def edit_tier_permissions(
			self,
			client_id,
			tier_id,
			length,
			shareable,
			group_bits,
		):
		#TODO i don't care about allowing independent length and shareable for each permission
		#TODO but this is where it would go
		client_id, client_id_bytes = parse_id(client_id)
		tier_id = int(tier_id)
		length = int(length)
		if shareable:
			shareable = 1
		else:
			shareable = 0
		self.connection.execute(
			self.tier_permissions.delete().where(
				and_(
					self.tier_permissions.c.client_id == client_id_bytes,
					self.tier_permissions.c.tier_id == tier_id,
				)
			)
		)
		permissions = []
		for scope, bits in group_bits.items():
			if bytes == type(bits):
				bits = int.from_bytes(bits, 'big')
			else:
				bits = int(bits)
			if 0 == bits:
				continue
			permissions.append({
				'client_id': client_id_bytes,
				'tier_id': tier_id,
				'length': length,
				'shareable': shareable,
				'scope': str(scope),
				'group_bits': bits,
			})
		if permissions:
			# sqlite needs smaller chunks for mass insertion
			i = 0
			per_insert = 50
			while permissions:
				current_chunk = permissions[:50]
				self.connection.execute(
					self.tier_permissions.insert().values(current_chunk)
				)
				del permissions[:50]

	def populate_client_permissions(self, client):
		self.populate_client_tiers(client)
		for tier in client.tiers.values():
			tier['permissions'] = []
		result = self.connection.execute(
			self.tier_permissions.select().where(
				self.tier_permissions.c.client_id == client.id_bytes
			)
		).fetchall()
		for row in result:
			tier_id = row[self.tier_permissions.c.tier_id]
			if not tier_id in client.tiers:
				continue
			permission = {
				'length': row[self.tier_permissions.c.length],
				'shareable': False,
				'scope': row[self.tier_permissions.c.scope],
				'group_bits': row[self.tier_permissions.c.group_bits],
			}
			if row[self.tier_permissions.c.shareable]:
				permission['shareable'] = True
			client.tiers[tier_id]['permissions'].append(permission)

	def populate_tier_permissions(self, tier):
		tier['permissions'] = []
		result = self.connection.execute(
			self.tier_permissions.select().where(
				self.tier_permissions.c.tier_id == tier['id']
			)
		).fetchall()
		for row in result:
			permission = {
				'length': row[self.tier_permissions.c.length],
				'shareable': False,
				'scope': row[self.tier_permissions.c.scope],
				'group_bits': row[self.tier_permissions.c.group_bits],
			}
			if row[self.tier_permissions.c.shareable]:
				permission['shareable'] = True
			tier['permissions'].append(permission)
