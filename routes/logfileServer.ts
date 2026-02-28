/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/') && !file.includes('..') && !file.includes('\\')) {
      const safePath = path.normalize(file).replace(/^(\.\.[\\/])+/, '')
      const fullPath = path.resolve('logs/', safePath)
      const baseDir = path.resolve('logs/')
      
      if (!fullPath.startsWith(baseDir)) {
        res.status(403)
        next(new Error('Access denied!'))
        return
      }
      
      const stream = require('fs').createReadStream(fullPath)
      stream.on('error', () => {
        res.status(404)
        next(new Error('File not found'))
      })
      stream.pipe(res)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
