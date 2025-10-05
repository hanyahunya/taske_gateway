package com.hanyahunya.gateway;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements WebFilter {

    @Value("${jwt.accesstoken.secret}")
    private String accessSecret;

    private SecretKey accessKey;

    @PostConstruct
    public void init() {
        accessKey = Keys.hmacShaKeyFor(accessSecret.getBytes(StandardCharsets.UTF_8));
    }

    // Reactive Redis Template을 주입받아 비동기적으로 Redis와 통신
    private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

    // Redis 블랙리스트 키의 앞부분
    private static final String BLACKLIST_KEY_PREFIX = "blacklist:user:";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        //  /auth/** 경로의 요청은 필터 건너뜀
        if (path.startsWith("/auth/")) {
//            log.info("認証フィルターをスキップします。パス: {}", path);
            return chain.filter(exchange);
        }

        // Authorization 헤더 존재 여부 및 "Bearer " 로 시작하는지 확인
        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, "Authorizationヘッダーがありません。");
        }

        String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return onError(exchange, "Authorizationヘッダーの形式が正しくありません。");
        }
        String token = authorizationHeader.substring(7);

        // Mono.fromCallable() : 잠재적으로 스레드를 차단할수있는 동기코드가 있다 리액티브 시스템에 알려주는거 
        return Mono.fromCallable(() -> parseJwt(token))
                /*
                 * 이 코드가 실행되는 현재 스레드는 Netty의 핵심 이벤트 루프 스레드기에, 멈추면 안됨.
                 * -> .subscribeOn() 은 지금할 작업 (parseJwt) 는 시간이 걸리니 Netty의 이벤트루프한테 처리하지 말라고 알려줌
                 * -> .subscribeOn() 이 작업을 Schedulers.boundedElastic() 이 스레드풀에있는 스레드한테 맡김.
                 * -> 위 단계와 동시에 이벤트 루트 스레드는 다른 요청 처리하러감
                 * 
                 * .subscribeOn() : 바로 앞의 작업(fromCallable) 을 어떤 스레드에서 실행할지 지정하는 역할
                 * Schedulers.boundedElastic() : Project Reactor가 제공하는 특별한 스레드 풀, 이 스레드 풀은 cpu를 많이 사용하거나 i/o 대기가 필요한 블로킹 작업을 처리하기에 최적화 되어있음
                 */
                .subscribeOn(Schedulers.boundedElastic())
                // 앞의 작업이 끝나면 결과물(claim) 로 또 다른 비동기작업 하라는 거
                .flatMap(claims -> {
                    String userId = claims.getSubject();
                    String role = claims.get("role", String.class);

                    /*
                     * reactiveRedisTemplate.hasKey() 는 기존 동기방식과 다르게 응답을 기다리지 않고 나중에 true 혹은 false를 줄게 하고 또다른 약속 Mono<Boolean>을 즉시 반환
                     *
                     * .flatMap() 은 위와 같이 reactiveRedisTemplate.hasKey(BLACKLIST_KEY_PREFIX + userId) 이 작업이 끝나면 그 값(Boolean)으로 처리하게 넣는거
                     */
                    return reactiveRedisTemplate.opsForValue().get(BLACKLIST_KEY_PREFIX + userId)
                            .flatMap(compromisedAtStr -> {
                                long compromisedAt = Long.parseLong(compromisedAtStr);
                                long tokenIssuedAt = claims.getIssuedAt().getTime() / 1000L;
                                if (tokenIssuedAt < compromisedAt) {
                                    return onError(exchange, "無効化されたトークンです。ユーザーID:" + userId);
                                }

                                /* 더미 엔드포인트 */
                                if (path.startsWith("/token/verify")) {
                                    exchange.getResponse().setStatusCode(HttpStatus.OK);
                                    return exchange.getResponse().setComplete();
                                }

                                // 도난 발생 이후에 발급된 새 토큰이면, 정상 처리
                                return passThrough(exchange, chain, userId, role);
                            })
                            /*
                             * .switchIfEmpty : 만약 compromisedAtStr가 비었으면 실행
                             * Mono.defer() : Mono-나중에 이렇게 실행할거야 라고 설계도만 만들어놓음 (매우 중요)
                             *
                             * 이벤트 루프 스레드 (Netty)는 뭘 실행할지 계획만 세우고, Mono 라는 설계도를 받고 다른 일 하러감.
                             * 구독단계에서 Spring Webflux가 이제 실행해! 라고 구독신호 보내면 아까 받은 설계도에 적힌 코드가 순서대로 실행됨.
                             *
                             * 만약 Mono.defer() 가 없으면 설계도를 만드는 과정에서 아직 존재하지 않은 userId, role을 쓰면 변수를 못찾고 오류.
                             * -> 이를 해결하기 위해 Mono.defer로 구독 전에 실행 안되게 지연.
                             */
                            .switchIfEmpty(Mono.defer(() -> {

                                /* 더미 엔드포인트 */
                                if (path.startsWith("/token/verify")) {
                                    exchange.getResponse().setStatusCode(HttpStatus.OK);
                                    return exchange.getResponse().setComplete();
                                }

                                return passThrough(exchange, chain, userId, role);
                            }));
                })
                // 토큰 파싱중 예외발생시 (만료, 서명 오류 등) 401 반환
                .onErrorResume(e -> onError(exchange, "無効なトークンです。"));
    }

    private Mono<Void> passThrough(ServerWebExchange exchange, WebFilterChain chain, String userId, String role) {
        // 블랙리스트 없을시 헤더에 토큰정보 파싱 및 기존 액세스 토큰 헤더 제거
        // 표준 헤더가 아닌건 X- 붙이기
        ServerHttpRequest newRequest = exchange.getRequest().mutate()
                .header("X-User-ID", userId)
                .header("X-User-Role", role)
                .headers(httpHeaders -> httpHeaders.remove(HttpHeaders.AUTHORIZATION))
                .build();

        log.info("認証に成功しました。ユーザーID: {}", userId);
        return chain.filter(exchange.mutate().request(newRequest).build()); // Mono<Void>
    }

    private Claims parseJwt(String token) {
        return Jwts.parser()
                .verifyWith(accessKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err) {
        log.error("認証エラー: {}, ステータス: {}", err, HttpStatus.UNAUTHORIZED);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }
}