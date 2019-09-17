{-# LANGUAGE ApplicativeDo, RecordWildCards #-}

module Main where

import Control.Monad (replicateM)
import Data.Binary.Get
import Data.ByteString.Lazy.Char8 (unpack)
import Data.ByteString.Lazy.Internal (ByteString(..))
import Data.Int (Int16, Int32)
import Data.List (sortBy)
import Data.Ord (comparing)
import Data.Semigroup ((<>))
import Data.Time
import Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import GHC.Int (Int64)
import Options.Applicative
import Text.Printf (printf)
import qualified Data.ByteString.Lazy as BL

timeOffset :: DiffTime
timeOffset  = 3
validQuoteType :: String
validQuoteType  = "B6034"
timeZoneKST :: TimeZone
timeZoneKST  = TimeZone (9 * 60) False "KST"

data BlockType = HeaderGlobal
               | HeaderPcap
               | HeaderEthe
               | HeaderIPv4
               | HeaderUDP
               | PackageQuote
               | PackagePcap

lengthBlock :: BlockType   -> Int
lengthBlock    HeaderGlobal = 24
lengthBlock    HeaderPcap   = 16
lengthBlock    HeaderEthe   = 14
lengthBlock    HeaderIPv4   = 20
lengthBlock    HeaderUDP    = 8
lengthBlock    PackageQuote = 215
lengthBlock    PackagePcap  = 257

data PcapHeader = PcapHeader
    { pcapTsSec   :: Int32
    , pcapTsUsec  :: Int32
    , pcapInclLen :: Int32
    , pcapOrigLen :: Int32 }

getPcapHeader :: Get PcapHeader
getPcapHeader  = PcapHeader <$> getInt32le
                            <*> getInt32le
                            <*> getInt32le
                            <*> getInt32le

data UDPHeader = UDPHeader
    { udpSourPort :: Int16
    , udpDestPort :: Int16
    , udpLength   :: Int16
    , udpChecksum :: Int16 }

getUDPHeader :: Get UDPHeader
getUDPHeader  = UDPHeader <$> getInt16be
                          <*> getInt16be
                          <*> getInt16be 
                          <*> getInt16be

calcPacketTime :: Int32 -> Int32 -> UTCTime
calcPacketTime sec uSec = posixSecondsToUTCTime . realToFrac $ secs
    where
        secs :: Double
        secs = (fromIntegral sec) + (fromIntegral uSec) * 10^^(-6 :: Integer)

calcAcceptTime :: UTCTime -> TimeZone -> Integer -> UTCTime
calcAcceptTime (UTCTime day _) tz t = zonedTimeToUTC at
    where 
        at  = ZonedTime lt tz
        lt  = LocalTime day tod
        tod = TimeOfDay (fromIntegral h) (fromIntegral m) s'
        s'  = (fromIntegral s) + (fromIntegral u) / 100
        u   = t    `mod` 100; t'   = t   `div` 100
        s   = t'   `mod` 100; t''  = t'  `div` 100
        m   = t''  `mod` 100; t''' = t'' `div` 100
        h   = t''' `mod` 100

showTime :: TimeZone -> UTCTime -> Int -> String
showTime tz t prec = formatTime defaultTimeLocale ("%F %T%" ++ show prec ++ "Q (%Z)") t'
    where
        t' = utcToZonedTime tz t

getString :: Int64 -> Get String
getString n = do bs <- getLazyByteString n
                 return $ unpack bs

getInteger :: Int64 -> Get Integer
getInteger n = do s <- getString n
                  return (read s :: Integer)

data Trade = Trade
    { price :: Integer
    , qty   :: Integer }

showTrade :: Trade -> String
showTrade (Trade p q) = printf "%7d@%-4d" q p

showTrades :: [Trade] -> String
showTrades ts = foldr (\t -> (showTrade t ++) . (" "++)) "" ts

getTrade :: Get Trade
getTrade  = Trade <$> getInteger 5
                  <*> getInteger 7

getTrades :: Int -> Get [Trade]
getTrades n = replicateM n getTrade

data Quote = Quote
    { quoteType  :: String
    , issueCode  :: String
    , bids       :: [Trade]
    , asks       :: [Trade]
    , acceptTime :: UTCTime
    , packetTime :: UTCTime
    , timeZone   :: TimeZone }

sortByTime :: [Quote] -> [Quote]
sortByTime  = sortBy $ comparing acceptTime

sortQuotes :: [Quote] -> [Quote]
sortQuotes []       = []
sortQuotes qs@(q:_) = lqs' ++ sortQuotes (rqs' ++ rqs)
    where 
        (lqs', rqs') = span (prd timeOffset) lqsSorted
        lqsSorted    = sortByTime lqs
        (lqs, rqs)   = span (prd (timeOffset * 2)) qs
        prd n    = ((prd' n) . utctDayTime . packetTime)
        prd' n t = (t >= pt) && (t <= pt + n) 
        pt       = utctDayTime . packetTime $ q 

showQuote :: Quote -> String
showQuote (Quote _ ic bs as at pt tz) = 
    showTime tz pt 10 ++ " " ++
    showTime tz at 2 ++ " " ++
    ic ++ " " ++
    showTrades (reverse bs) ++ " " ++
    showTrades as

getQuote :: TimeZone -> UTCTime -> Get Quote
getQuote timeZone packetTime = do
    quoteType <- getString 5
    issueCode <- getString 12
    skip 12
    bids <- getTrades 5
    skip 7
    asks <- getTrades 5
    skip 50
    time <- getInteger 8
    skip 1
    let acceptTime = calcAcceptTime packetTime timeZone time 
    return Quote{..} 

getMQuote :: Get (Maybe Quote)
getMQuote  = do
    pcapHeader <- getPcapHeader
    if (fromIntegral $ pcapInclLen pcapHeader) == lengthBlock PackagePcap
        then do skip $ lengthBlock HeaderEthe
                skip $ lengthBlock HeaderIPv4
                udpHeader <- getUDPHeader
                quoteType <- lookAhead $ getString 5
                if (fromIntegral $ udpLength udpHeader) - lengthBlock HeaderUDP 
                    == lengthBlock PackageQuote 
                 && quoteType == validQuoteType
                    then let packetTime = calcPacketTime (pcapTsSec pcapHeader)
                                                         (pcapTsUsec pcapHeader)
                          in do quote <- getQuote timeZoneKST packetTime
                                return $ Just quote
                    else do skip $ (fromIntegral $ udpLength udpHeader) - lengthBlock HeaderUDP
                            return Nothing
        else do skip (fromIntegral $ pcapInclLen pcapHeader)
                return Nothing

parseQuotes :: BL.ByteString -> [Quote]
parseQuotes c =
    let r = runGetOrFail getMQuote c
     in case r of 
        Right (c', _, mQuote) -> 
            if c' == Empty
                then case mQuote of 
                    Just quote -> [quote]
                    Nothing    -> []
                else case mQuote of 
                    Just quote -> quote : parseQuotes c'
                    Nothing    -> parseQuotes c'
        Left (c', _, _) ->
            if c' == Empty then []
                           else parseQuotes c'

printQuotes :: Bool -> BL.ByteString -> IO ()
printQuotes r c = mapM_ (putStrLn . showQuote) $ maybeSort $ parseQuotes c
    where maybeSort = if r then sortQuotes else id 

printPcapFile :: PcapArgs -> IO ()
printPcapFile (PcapArgs f r) = do 
    c <- BL.readFile f
    let c' = BL.drop (fromIntegral $ lengthBlock HeaderGlobal) c
    printQuotes r c'

data PcapArgs = PcapArgs
    { file  :: String
    , rFlag :: Bool }

main :: IO ()
main  = do pcapArgs <- execParser pcapArgsParser
           printPcapFile pcapArgs
    where
        pcapArgsParser :: ParserInfo PcapArgs
        pcapArgsParser  = info (helper <*> programArgs)
            ( fullDesc
           <> header "Parser Quote - Parse and print quote messages from a market data feed.")
        programArgs :: Parser PcapArgs
        programArgs  = do
            file <- argument str 
                ( metavar "FILE"
               <> help "Input file of type '.pcap'")
            rFlag <- switch 
                ( short 'r' 
               <> help "Re-order messages according to quote accept time")
            pure PcapArgs{..}

