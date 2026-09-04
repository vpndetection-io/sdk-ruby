# frozen_string_literal: true

# Which plan tiers this run can observe, and the secret each one needs.
#
# A tier is observable only when its secret holds something non-empty. Actions
# interpolates a secret that does not exist to an EMPTY STRING rather than
# leaving the variable unset, and a client built with an empty key sends no
# authorization header at all, so an empty key runs as a second unauthenticated
# client and every comparison against it is vacuously true.

module Tiers
  # Ascending, one rung per plan tier. `widens` is what the rung promises against
  # whichever observable rung sits below it: a paid tier serves strictly more
  # than the tier under it, while a free key and no key at all are the same
  # entitlement reached two ways.
  #
  # Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
  # turns a pricing change into a red SDK build; the relation between the tiers
  # is what the client actually has to keep.
  RUNGS = [
    { tier: 'unauth', secret: nil, widens: false },
    { tier: 'free', secret: 'VPNDETECTION_STAGING_KEY_FREE', widens: false },
    { tier: 'starter', secret: 'VPNDETECTION_STAGING_KEY_STARTER', widens: true },
    { tier: 'scale', secret: 'VPNDETECTION_STAGING_KEY_SCALE', widens: true },
    { tier: 'max', secret: 'VPNDETECTION_STAGING_KEY_MAX', widens: true },
  ].freeze

  module_function

  def unauth
    RUNGS.first
  end

  def max
    RUNGS.last
  end

  def key(rung)
    return nil if rung[:secret].nil?

    value = ENV.fetch(rung[:secret], '').strip
    value.empty? ? nil : value
  end

  # A reason, or nil when this tier can be exercised.
  def skip_for(rung)
    return nil if rung[:secret].nil? || key(rung)

    "#{rung[:secret]} is not set, so the #{rung[:tier]} tier cannot be exercised"
  end

  def observable
    RUNGS.select { |rung| skip_for(rung).nil? }
  end

  # The ladder needs two rungs to say anything. The unauthenticated one is always
  # there, so this only fires when no tier secret at all is configured.
  def ladder_skip
    return nil if observable.length > 1

    'no tier secret is set, so there is no ladder to compare'
  end

  # Surfaced on the workflow run itself, so a skip is visible without opening the
  # log and reading to the end of it.
  def notice(message)
    return puts("==> #{message}") unless ENV['GITHUB_ACTIONS'] == 'true'

    puts "::notice title=Integration::#{message}"
  end
end
