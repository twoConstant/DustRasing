package com.ssafy.rasingdust.domain.user.dto.response;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;
import lombok.Data;
import org.springframework.data.domain.Slice;

@Data
@Schema(description = "무한 스크롤 응답 데이터")
public class SliceResponse<T> {
    @Schema(description = "응답 실제 데이터의 Collection")
    protected final List<T> content;
    @Schema(description = "다음 조회할 페이지의 번호")
    protected final int currentPage;
    @Schema(description = "content 개수")
    protected final int size;
    @Schema(description = "첫 번째 페이지 여부")
    protected final boolean first;
    @Schema(description = "마지막 페이지 여부")
    protected final boolean last;

    public SliceResponse(Slice<T> sliceContent) {
        this.content = sliceContent.getContent();
        // page 번호가 1번부터 시작되도록
        this.currentPage = sliceContent.getNumber() + 1;
        this.size = sliceContent.getSize();
        this.first = sliceContent.isFirst();
        this.last = sliceContent.isLast();
    }

}
