/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    
    if (!toUrl) {
      res.status(400)
      next(new Error('Missing redirect URL'))
      return
    }
    
    try {
      const url = new URL(toUrl)
      if (!security.isRedirectAllowed(toUrl)) {
        res.status(406)
        next(new Error('Unrecognized target URL for redirect: ' + toUrl))
        return
      }
      
      const allowedHosts = ['github.com', 'blockchain.info', 'explorer.dash.org', 'etherscan.io', 'spreadshirt.com', 'spreadshirt.de', 'stickeryou.com', 'leanpub.com']
      if (!allowedHosts.some(host => url.hostname.endsWith(host))) {
        res.status(406)
        next(new Error('Redirect to external domain not allowed: ' + url.hostname))
        return
      }
      
      if (url.protocol !== 'http:' && url.protocol !== 'https:') {
        res.status(406)
        next(new Error('Invalid protocol for redirect'))
        return
      }
      
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      
      res.setHeader('Location', toUrl)
      res.status(302).end()
    } catch (err) {
      res.status(406)
      next(new Error('Invalid URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
