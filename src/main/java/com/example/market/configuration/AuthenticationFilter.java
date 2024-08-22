package com.example.market.configuration;

import com.example.market.dto.request.IntrospectRequest;

import com.example.market.dto.response.IntrospectResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationFilter implements GlobalFilter, Ordered {
    ObjectMapper objectMapper;
    WebClient webClient;

    @NonFinal
    String[] publicEndpoints = {"/market_auth/auth/.*", "/market_trade/post/.*","/market_notification/notification/.*"};

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        List<String> authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION);
        if(isPublicEndpoints(exchange.getRequest())){
          return   chain.filter(exchange);
        }

        if (CollectionUtils.isEmpty(authHeader)) {
            return unAuthenticated(exchange.getResponse());
        }

        String token = authHeader.get(0).replace("Bearer ", "");

        return introspectToken(token)
                .flatMap(introspectResponse -> {
                    if (introspectResponse.isValid()) {
                        return chain.filter(exchange);
                    } else {
                        return unAuthenticated(exchange.getResponse());
                    }
                })
                .onErrorResume(throwable -> {
                    return unAuthenticated(exchange.getResponse());
                });

    }

    @Override
    public int getOrder() {
        return -1;
    }

    private  boolean isPublicEndpoints(ServerHttpRequest request){
        return Arrays.stream(publicEndpoints).anyMatch(s -> request.getURI().getPath().matches(s));
    }


    Mono<Void> unAuthenticated(ServerHttpResponse response) {
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("code", 44444);
        errorDetails.put("message", "UNAUTHENTICATED");

        String body;
        try {
            // Chuyển đổi Map thành JSON
            body = objectMapper.writeValueAsString(errorDetails);
        } catch (JsonProcessingException exception) {
            throw new RuntimeException(exception);
        }

        // Đặt mã lỗi và loại nội dung cho phản hồi
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

        // Ghi phản hồi dưới dạng JSON
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body.getBytes())));
    }


    private Mono<IntrospectResponse> introspectToken(String token) {
        return webClient.post()
                .uri("/auth/introspect")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(IntrospectRequest.builder().token(token).build())
                .retrieve()
                .bodyToMono(IntrospectResponse.class)
                .onErrorResume(ex -> {
                    log.error("Token introspection failed", ex);
                    return Mono.empty();  // Xử lý lỗi khi không thể lấy phản hồi
                });
    }
}